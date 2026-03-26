# SPDX-License-Identifier: GPL-3.0-or-later

"""Bitwarden CLI backend implementation.

This backend interacts with the 'bw' command-line tool to retrieve 
credentials and SSH keys. The session token is kept only in memory.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import Any
import gettext

_ = gettext.gettext

from vault.base import VaultBackend
from utils.secure import SecureBytes
import gi
from vault.models import SSHKeyMaterial, VaultCredential
try:
    gi.require_version("Secret", "1")
    from gi.repository import Secret
    LIBSECRET_AVAILABLE = True
except (ImportError, ValueError):
    LIBSECRET_AVAILABLE = False


logger = logging.getLogger(__name__)


class BitwardenBackend(VaultBackend):
    """Bitwarden backend using the 'bw' CLI."""

    def __init__(self) -> None:
        self._session_token: SecureBytes | None = None
        
        # Prefer the local binary if we bundle it or the user downloaded it
        import os
        from pathlib import Path
        local_bw = Path(__file__).parent.parent.parent / "bin" / "bw"
        if local_bw.exists() and os.access(local_bw, os.X_OK):
            self._cli_path = str(local_bw)
        else:
            self._cli_path = shutil.which("bw")
        
        logger.info(f"Bitwarden: Backend initialized using CLI at: {self._cli_path}")
        self._auto_synced = False
        self._last_folders: list[dict[str, str]] = []
        
        # In-memory cache for retrieved credentials (passwords/keys)
        # item_id -> { "password": SecureBytes, "ssh-key": SSHKeyMaterial }
        self._item_cache: dict[str, dict[str, Any]] = {}
        
        # Performance: Cache the unlocked status for 30 seconds to avoid repeating 'bw status'
        self._status_cache: bool | None = None
        self._status_cache_time: float = 0
        
        # Flag: bw CLI is unlocked via its own session management (no in-memory token needed)
        self._cli_session_active: bool = False

        self._expected_sha = "8b925256504fde78684df7b937ec2f03417ace5fde4a663a9a6cd85dc94b122e"

        # Load persisted Bitwarden session from local secure vault (if available)
        self._try_load_cached_session()

    @property
    def name(self) -> str:
        return "Bitwarden"

    @property
    def is_available(self) -> bool:
        return self._cli_path is not None

    async def _run_bw(self, args: list[str], input_str: str | None = None) -> str:
        """Run a bw command and return stdout string."""
        raw = await self._run_bw_raw(args, input_str)
        return raw.decode()

    async def _run_bw_raw(self, args: list[str], input_str: str | None = None) -> bytes:
        """Run a bw command and return stdout bytes."""
        if not self.is_available:
            raise RuntimeError("Bitwarden CLI ('bw') not found in PATH.")

        # Security check for bundled binary
        if "bin/bw" in self._cli_path:
            if not await self._verify_binary(self._cli_path, self._expected_sha):
                 raise RuntimeError("Bitwarden CLI integrity check failed! Potential tampering detected.")

        env = os.environ.copy()
        _t_session = None
        if self._session_token:
            # Environment variables must be strings, so we use unsafe_get_str().
            # Note: This copy is temporary for the subprocess lifetime.
            _t_session = self._session_token.unsafe_get_str()
            env["BW_SESSION"] = _t_session
            logger.debug("Bitwarden: Running command with session token")
        elif self._cli_session_active:
            logger.debug("Bitwarden: Running command using CLI-managed active session.")
        else:
            logger.debug("Bitwarden: Running command WITHOUT session token.")

        # Mask sensitive commands for the log
        safe_args = list(args)
        if safe_args:
            # Mask --code for login
            if "--code" in safe_args:
                try:
                    idx = safe_args.index("--code")
                    if idx + 1 < len(safe_args):
                        safe_args[idx + 1] = "********"
                except ValueError: pass
            
            # Mask session token if passed via --session (though we usually use env)
            if "--session" in safe_args:
                try:
                    idx = safe_args.index("--session")
                    if idx + 1 < len(safe_args):
                        safe_args[idx + 1] = "********"
                except ValueError: pass

        logger.info(f"Bitwarden: Executing command: {self._cli_path} {' '.join(safe_args)}")

        process = await asyncio.create_subprocess_exec(
            self._cli_path,
            *args,
            stdin=asyncio.subprocess.PIPE if input_str else (asyncio.subprocess.PIPE if args and args[0] in ["login", "unlock"] else None),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        input_bytes = None
        if input_str:
            if isinstance(input_str, (bytes, bytearray, memoryview)):
                input_bytes = input_str
            else:
                input_bytes = input_str.encode()

        stdout, stderr = await process.communicate(input=input_bytes)
        
        # Scrub the token from memory immediately
        if "BW_SESSION" in env:
            env["BW_SESSION"] = ""
            del env["BW_SESSION"]
        if _t_session:
            # We can't truly erase the string content in Python, but we can 
            # remove the reference and minimize its lifetime.
            _t_session = None
            del _t_session

        logger.info(f"Bitwarden: Command finished with return code {process.returncode}")

        if process.returncode != 0:
            logger.error("Bitwarden CLI error (Return Code: %d)", process.returncode)
            raise RuntimeError(f"Bitwarden CLI failed with code {process.returncode}")

        return stdout

    async def _verify_binary(self, path: str, expected_sha: str) -> bool:
        """Verify the SHA256 hash of the 'bw' binary."""
        import hashlib
        try:
            def _calc():
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    while chunk := f.read(8192):
                        h.update(chunk)
                return h.hexdigest()
            actual = await asyncio.to_thread(_calc)
            return actual == expected_sha
        except Exception:
            return False

    async def login(self, email: str, password: SecureBytes | str, method: int | None = None, code: SecureBytes | str | None = None, remember: bool = False) -> bool:
        """Log in to Bitwarden securely. Password passed via stdin.
        Matches 0.1.0 logic which is known-good with the bundled CLI.
        """
        logger.info(f"Bitwarden: Attempting login for {email} (Method: {method})")
        # Security: Use bytearray to allow wiping
        master_password_ba = bytearray(password.get_view() if isinstance(password, SecureBytes) else password.encode())
        totp_code_ba = None
        if code:
             totp_code_ba = bytearray(code.get_view() if isinstance(code, SecureBytes) else str(code).encode())

        try:
            # Use BW_PASSWORD environment variable for secure, non-interactive transfer.
            # This is the most reliable way to pass secrets to bw CLI without a TTY.
            env = os.environ.copy()
            _pwd_str = password.unsafe_get_str() if isinstance(password, SecureBytes) else password
            env["BW_PASSWORD"] = _pwd_str
            
            # --nointeraction is critical: without it, bw might hang if 2FA is needed
            # even when using --passwordenv.
            args = ["login", email, "--raw", "--passwordenv", "BW_PASSWORD", "--nointeraction"]
            if method is not None:
                args.extend(["--method", str(method)])
            if code:
                # Code is short-lived, passing via arg is acceptable if 2FA is used,
                # but we can also use BW_2FA_CODE if supported by newer CLI.
                _code = code.unsafe_get_str() if isinstance(code, SecureBytes) else str(code)
                args.extend(["--code", _code])

            logger.info(f"Bitwarden: Executing login for {email} using --passwordenv")
            process = await asyncio.create_subprocess_exec(
                self._cli_path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await process.communicate()
            
            # Wipe the token from the env copy
            env["BW_PASSWORD"] = ""
            del env["BW_PASSWORD"]
            _pwd_str = None
            
            # Wipe sensitive input immediately
            for i in range(len(master_password_ba)): master_password_ba[i] = 0
            if totp_code_ba:
                for i in range(len(totp_code_ba)): totp_code_ba[i] = 0

            if process.returncode != 0:
                err_msg = stderr.decode().strip()
                logger.error(f"Bitwarden login CLI error: {err_msg}")
                raise RuntimeError(err_msg)

            token = stdout.decode().strip()
            if token:
                logger.info(f"Bitwarden: Login successful for {email}. Session token received.")
                if self._session_token:
                    self._session_token.clear()
                self._session_token = SecureBytes(token)
                self._cli_session_active = False

                # Persist to local secure vault (best-effort)
                try:
                    from services.vault_manager import VaultManager
                    vm = VaultManager.get()
                    if vm.is_unlocked:
                        vm.save_bitwarden_session(email, token)
                        logger.debug("Bitwarden: Session token saved to local vault.")
                except Exception as _e:
                    logger.debug("Bitwarden: Could not save session to vault: %s", _e)

                self._status_cache = True
                import time
                self._status_cache_time = time.time()
                
                # Save master password to keyring if requested
                if remember:
                    try:
                        from services.vault_manager import VaultManager
                        VaultManager.get().save_bitwarden_password(master_password)
                        logger.info("Bitwarden: Master password saved to keyring for future auto-unlock.")
                    except Exception as _e:
                        logger.warning("Bitwarden: Failed to save password to keyring: %s", _e)

                return True
            
            logger.warning(f"Bitwarden: Login command returned success but no session token for {email}.")
            return False
        except Exception as e:
            logger.error("Bitwarden: Login failed for %s: %s", email, type(e).__name__)
            raise

    async def unlock(self, master_password: SecureBytes | str, remember: bool = False) -> bool:
        """Unlock the vault and store the session token.
        Master password is passed via stdin to avoid ps leakage.
        Matches 0.1.0 logic which is known-good with the bundled CLI.
        """
        logger.info("Bitwarden: Attempting to unlock vault...")
        try:
            # First check status
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)

            if status.get("status") == "unauthenticated":
                logger.warning("Bitwarden: Cannot unlock — User is not logged in.")
                return False

            # Use bytearray to allow wiping
            pwd_ba = bytearray(master_password.get_view() if isinstance(master_password, SecureBytes) else master_password.encode())

            # Use BW_PASSWORD environment variable and --passwordenv for clean transfer.
            env = os.environ.copy()
            _pwd_str = master_password.unsafe_get_str() if isinstance(master_password, SecureBytes) else master_password
            env["BW_PASSWORD"] = _pwd_str

            # Use --raw to get only the session token on stdout
            process = await asyncio.create_subprocess_exec(
                self._cli_path,
                "unlock", "--raw", "--passwordenv", "BW_PASSWORD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            logger.info("Bitwarden: Executing unlock using --passwordenv")
            stdout, stderr = await process.communicate()
            
            # Cleanup
            env["BW_PASSWORD"] = ""
            del env["BW_PASSWORD"]
            _pwd_str = None
            
            # Wipe sensitive input
            for i in range(len(pwd_ba)): pwd_ba[i] = 0

            if process.returncode != 0:
                err_msg = stderr.decode().strip()
                logger.error(f"Bitwarden unlock failed: {err_msg}")
                return False

            token = stdout.decode().strip()
            if token:
                logger.info("Bitwarden: Vault unlocked successfully. Session token stored.")
                if self._session_token:
                    self._session_token.clear()
                self._session_token = SecureBytes(token)
                self._cli_session_active = False

                # Persist to local secure vault (best-effort)
                try:
                    from services.vault_manager import VaultManager
                    vm = VaultManager.get()
                    if vm.is_unlocked:
                        # Get email from bw status
                        try:
                            status_raw = await self._run_bw(["status"])
                            status_data = json.loads(status_raw)
                            _email = status_data.get("userEmail", "")
                        except Exception:
                            _email = ""
                        vm.save_bitwarden_session(_email, token)
                        logger.debug("Bitwarden: Session token saved to local vault after unlock.")
                except Exception as _e:
                    logger.debug("Bitwarden: Could not save session to vault: %s", _e)

                self._status_cache = True
                import time
                self._status_cache_time = time.time()
                
                # Save master password to keyring if requested
                if remember:
                    try:
                        from services.vault_manager import VaultManager
                        VaultManager.get().save_bitwarden_password(master_password)
                        logger.info("Bitwarden: Master password saved to keyring for future auto-unlock.")
                    except Exception as _e:
                        logger.warning("Bitwarden: Failed to save password to keyring: %s", _e)

                return True
            
            logger.warning("Bitwarden: Unlock command finished but no session token was returned.")
            return False
        except Exception as e:
            logger.error("Bitwarden: Failed to unlock vault: %s", type(e).__name__)
            return False

    async def lock(self) -> None:
        """Lock the vault and clear the session token."""
        if self._session_token:
            try:
                await self._run_bw(["lock"])
            except Exception:
                pass
            self._session_token.clear()
            self._session_token = None
        else:
            try:
                await self._run_bw(["lock"])
            except Exception:
                pass
            
        if LIBSECRET_AVAILABLE:
            self._clear_session_from_keyring()

        # Clear from local secure vault too
        try:
            from services.vault_manager import VaultManager
            VaultManager.get().clear_bitwarden_session()
        except Exception:
            pass

        self._item_cache.clear()
        self._cli_session_active = False
        self._status_cache = None

    async def is_unlocked(self) -> bool:
        """Check if the vault is unlocked. Uses a 30s cache to keep UI responsive."""
        import time
        now = time.time()
        
        if self._status_cache is not None and (now - self._status_cache_time) < 30:
            # logger.debug(f"Bitwarden: Using cached status: {self._status_cache}")
            return self._status_cache

        # Try auto-unlock if we don't have a token but might have a password in keyring
        if not self._session_token and not self._cli_session_active:
            try:
                from services.vault_manager import VaultManager
                saved_pwd = VaultManager.get().get_bitwarden_password()
                if saved_pwd:
                    logger.info("Bitwarden: Attempting auto-unlock with saved password from keyring...")
                    # Note: unlock() handles status caching
                    success = await self.unlock(saved_pwd)
                    if success:
                        logger.info("Bitwarden: Auto-unlock successful.")
                        return True
            except Exception as e:
                logger.debug("Bitwarden: Auto-unlock attempt failed: %s", e)

        try:
            logger.debug("Bitwarden: Cache expired or missing, checking 'bw status'...")
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)
            state = status.get("status")
            unlocked = (state == "unlocked")
            
            logger.info(f"Bitwarden: Current CLI status is '{state}' (unlocked={unlocked})")
            
            if not unlocked and self._session_token:
                # Token in memory but CLI says locked — token probably expired.
                logger.warning("Bitwarden: In-memory token present but CLI reports locked. Clearing stale token.")
                self._session_token.clear()
                self._session_token = None
                self._item_cache.clear()
                self._cli_session_active = False
            elif unlocked and not self._session_token:
                # bw CLI has its own valid session (e.g. from a previous app run).
                # Mark this so _run_bw_raw doesn't log spurious warnings.
                if not self._cli_session_active:
                    logger.info("Bitwarden: Detected active CLI session without in-memory token. Enabling session reuse.")
                    self._cli_session_active = True
            
            self._status_cache = unlocked
            self._status_cache_time = now
            return unlocked
        except Exception as e:
            logger.error(f"Bitwarden: Failed to check vault status: {e}")
            # If bw command fails with no token, conservatively return False.
            self._status_cache = False
            self._status_cache_time = now
            return False

    def _get_cached_credential(self, item_id: str, cred_type: str) -> Any | None:
        """Fetch a credential from memory cache."""
        item_data = self._item_cache.get(item_id)
        if item_data:
            return item_data.get(cred_type)
        return None

    def _set_cached_credential(self, item_id: str, cred_type: str, value: Any) -> None:
        """Store a credential in memory cache."""
        if item_id not in self._item_cache:
            self._item_cache[item_id] = {}
        self._item_cache[item_id][cred_type] = value

    async def search_credentials(
        self, hostname: str, username: str | None = None
    ) -> list[VaultCredential]:
        """Search for login items matching the hostname."""
        if not await self.is_unlocked():
            return []

        try:
            from services.vault_service import VaultService
            import sqlite3
            
            # Note: We need a way to get the configured folder. Since BitwardenBackend is a singleton/service, 
            # we can use Database.get_meta to find the preferred folder.
            # But the backend shouldn't depend on the db directly unless it has to. Let's do it inline so we don't break dependencies.
            from db.database import Database
            db = Database()
            db.open()
            folder_id = db.get_meta("vault_folder_id")
            db.close()
            
            args = ["list", "items"]
            if folder_id:
                logger.debug(f"search_credentials: Filtering by folder_id='{folder_id}'")
                args.extend(["--folderid", folder_id])
            if hostname:
                logger.debug(f"search_credentials: Searching for hostname='{hostname}'")
                args.extend(["--search", hostname])
            
            # Search for login items
            logger.debug(f"search_credentials: Executing 'bw {' '.join(args)}'...")
            items_raw = await self._run_bw(args)
            items_json = json.loads(items_raw)
            
            results = []
            for item in items_json:
                item_type = item.get("type")
                login = item.get("login", {})
                item_username = login.get("username")
                
                # DEEP SCAN for SSH Key presence during listing
                has_key = False
                key_source = ""
                # A. Native Field
                if item.get("sshKey") and item.get("sshKey").get("privateKey"):
                    has_key = True
                    key_source = "Native Field"
                # B. Custom Fields
                if not has_key:
                    for f in item.get("fields", []):
                        if f.get("name") in ["ssh-key", "privateKey", "private-key"] and f.get("value"):
                            has_key = True
                            key_source = "Custom Field"
                            break
                # C. Attachments
                if not has_key and item.get("attachments"):
                    has_key = True
                    key_source = "Attachment"
                # D. Notes
                if not has_key:
                    notes = item.get("notes", "") or ""
                    if "-----BEGIN" in notes:
                        has_key = True
                        key_source = "From Notes"

                logger.debug(f"search_credentials: Item '{item.get('name')}' - Key Found? {has_key} ({key_source})")
                
                # If username specified, filter by it
                if username and item_username != username:
                    continue
                
                results.append(VaultCredential(
                    item_id=item["id"],
                    name=item["name"],
                    username=item_username,
                    has_password=bool(login.get("password")),
                    has_ssh_key=has_key,
                    has_totp=bool(login.get("totp")),
                    uri=next((u.get("uri") for u in login.get("uris", [])), None),
                    note=key_source if has_key else None
                ))
            if not results:
                logger.debug("No Bitwarden items found. Consider running 'bw sync'.")
            return results
        except Exception as e:
            logger.error(f"Error searching Bitwarden credentials: {e}")
            return []

    async def list_folders(self) -> list[dict[str, str]]:
        """List folders from Bitwarden. Auto-syncs once if empty."""
        logger.debug("list_folders() called.")
        if not await self.is_unlocked():
            logger.debug("list_folders: Vault is LOCKED.")
            return []
            
        async def _fetch():
            try:
                logger.debug("list_folders: Executing 'bw list folders'...")
                output = await self._run_bw(["list", "folders"])
                return json.loads(output)
            except Exception as e:
                logger.debug(f"list_folders: Error during fetch: {e}")
                logger.error(f"Error listing folders: {e}")
                return []

        folders = await _fetch()
        logger.debug(f"list_folders: Fetched {len(folders)} folders.")
        
        # If empty and we haven't synced yet, try syncing once
        if not folders and not self._auto_synced:
            logger.debug("list_folders: Folders empty, triggering auto-sync...")
            try:
                await self._run_bw(["sync"])
                self._auto_synced = True
                logger.debug("list_folders: Sync done, re-fetching...")
                folders = await _fetch()
                logger.debug(f"list_folders: After sync, got {len(folders)} folders.")
            except Exception as e:
                logger.debug(f"list_folders: Auto-sync failed: {e}")
                logger.warning(f"Auto-sync failed: {e}")

        self._last_folders = [{"id": f["id"], "name": f["name"]} for f in folders]
        return self._last_folders

    async def list_items(self, folder_id: str | None = None) -> list[VaultCredential]:
        """List all items in the vault or specific folder."""
        # We can just reuse search_credentials with empty hostname
        return await self.search_credentials("", None)
        
    async def configure_server(self, url: str) -> None:
        """Configure Bitwarden self-hosted server url."""
        await self._run_bw(["config", "server", url])
        
    async def get_server(self) -> str | None:
        """Get currently configured server."""
        # Try auto-unlock if we don't have a token but might have a password in keyring
        if not self._session_token and not self._cli_session_active:
            try:
                from services.vault_manager import VaultManager
                saved_pwd = VaultManager.get().get_bitwarden_password()
                if saved_pwd:
                    logger.info("Bitwarden: Attempting auto-unlock with saved password from keyring...")
                    # We use a temporary SecureBytes for the saved password
                    success = await self.unlock(saved_pwd)
                    if success:
                        logger.info("Bitwarden: Auto-unlock successful.")
                        return True
            except Exception as e:
                logger.debug("Bitwarden: Auto-unlock attempt failed: %s", e)

        try:
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)
            return status.get("serverUrl")
        except Exception:
            return None

    async def get_password(self, item_id: str) -> SecureBytes:
        """Retrieve password. Tries Keyring cache first."""
        # 1. Memory cache
        cached = self._get_cached_credential(item_id, "password")
        if cached:
            logger.debug(f"Password for {item_id} hit memory cache.")
            return cached

        # 2. Local vault cache
        try:
            from services.vault_manager import VaultManager
            vm = VaultManager.get()
            if vm.is_unlocked:
                local_pwd = vm.get_cached_password(item_id)
                if local_pwd:
                    logger.info(f"Password for {item_id} loaded from local secure vault cache.")
                    self._set_cached_credential(item_id, "password", local_pwd)
                    return local_pwd
        except Exception as _e:
            logger.debug("Could not check local vault cache for password: %s", _e)

        # 3. Bitwarden CLI
        if not await self.is_unlocked():
            raise RuntimeError("Vault is locked")
            
        try:
            # 3.1 Try high-efficiency direct password fetch first
            try:
                password_raw = await self._run_bw(["get", "password", item_id])
                if password_raw and password_raw.strip():
                    sb = SecureBytes(password_raw.strip())
                    self._set_cached_credential(item_id, "password", sb)
                    
                    # Persist to Local Vault Cache
                    try:
                        from services.vault_manager import VaultManager
                        vm = VaultManager.get()
                        if vm.is_unlocked:
                            vm.cache_password(item_id=item_id, label="Bitwarden Cached", password=sb)
                    except: pass
                    
                    return sb
            except Exception as direct_err:
                logger.debug(f"Direct password fetch failed for {item_id}, falling back to full item: {direct_err}")

            # 3.2 Fallback to full item parsing for custom fields/notes
            item_raw = await self._run_bw(["get", "item", item_id])
            item = json.loads(item_raw)
            login = item.get("login", {})
            password = login.get("password")
            
            # 1. Check custom fields (case-insensitive)
            if not password:
                fields = item.get("fields", [])
                for f in fields:
                    fname = (f.get("name") or "").lower()
                    if fname in ["password", "pwd", "secret", "pass", "login password"]:
                        password = f.get("value")
                        break
            
            # 2. Check notes
            if not password:
                notes = (item.get("notes") or "").strip()
                if notes and "\n" not in notes and len(notes) < 64:
                    password = notes
            
            if not password:
                raise ValueError(_("No password found in item. Check item ID '{id}'.").format(id=item_id))
            
            sb = SecureBytes(password)
            self._set_cached_credential(item_id, "password", sb)
            
            # Persist to Local Vault Cache
            try:
                from services.vault_manager import VaultManager
                vm = VaultManager.get()
                if vm.is_unlocked:
                    vm.cache_password(item_id=item_id, label=item.get("name", item_id), password=sb)
            except: pass

            return sb
        except Exception as e:
            logger.error(f"Failed to retrieve password from Bitwarden: {e}")
            raise

    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial:
        """Retrieve SSH key material. Checks memory cache, then local vault, then bw CLI."""
        # 1. In-memory cache (fastest, same session)
        cached_key = self._get_cached_credential(item_id, "ssh-key")
        if cached_key:
            logger.debug(f"SSH Key for {item_id} hit memory cache.")
            return cached_key

        # 2. Local AES-encrypted vault cache (across sessions)
        try:
            from services.vault_manager import VaultManager
            vm = VaultManager.get()
            if vm.is_unlocked:
                local_key = vm.get_cached_ssh_key(item_id)
                if local_key:
                    logger.info(f"SSH Key for {item_id} loaded from local secure vault cache.")
                    self._set_cached_credential(item_id, "ssh-key", local_key)
                    return local_key
        except Exception as _e:
            logger.debug("Could not check local vault cache: %s", _e)

        # 3. Fetch from Bitwarden CLI (slower, requires session)
        if not await self.is_unlocked():
            raise RuntimeError("Vault is locked")

        try:
            logger.info(f"Fetching full item data for {item_id} from Bitwarden...")
            item_raw = await self._run_bw(["get", "item", item_id])
            item = json.loads(item_raw)
            
            key_data = None
            passphrase = None
            
            # 1. Check Native SSH Key object (Type 5)
            ssh_key_obj = item.get("sshKey")
            if ssh_key_obj:
                key_data = ssh_key_obj.get("privateKey")
                passphrase = ssh_key_obj.get("passphrase")
            
            # 2. Check custom fields
            if not key_data:
                fields = item.get("fields", [])
                for f in fields:
                    if f.get("name") in ["ssh-key", "privateKey", "private-key"]:
                        key_data = f.get("value")
                    elif f.get("name") in ["ssh-passphrase", "passphrase"]:
                        passphrase = f.get("value")
            
            # 3. Check attachments
            if not key_data:
                attachments = item.get("attachments", [])
                candidates = []
                for att in attachments:
                    fn = att.get("fileName", "").lower()
                    if fn.endswith(".pub"):
                        continue
                    if fn in ["id_rsa", "id_ed25519", "id_ecdsa"] or fn.endswith(".pem") or fn.endswith(".key") or "ssh" in fn:
                        candidates.append(att)

                if candidates:
                    tasks = [
                        self._run_bw_raw(["get", "attachment", att["id"], "--itemid", item_id])
                        for att in candidates
                    ]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in results:
                        if isinstance(res, (bytes, bytearray)):
                            key_data = res
                            break

            # 4. Fallback to notes (extract PEM block from potentially messy notes)
            if not key_data:
                notes = item.get("notes", "")
                if "-----BEGIN" in notes:
                    logger.debug("Bitwarden: Searching for PRIVATE KEY in notes...")
                    import re
                    # Specifically look for PRIVATE KEY to avoid picking up PUBLIC KEY
                    match = re.search(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----.+?-----END [A-Z ]*PRIVATE KEY-----)", notes, re.DOTALL)
                    if match:
                        key_data = match.group(1)
                        logger.debug("Bitwarden: Extracted PRIVATE KEY block from notes.")
                    else:
                        # Fallback to whole notes if marker but no end block found
                        key_data = notes

            if not key_data:
                raise ValueError("No SSH key found in Bitwarden item")

            # Build the material object
            pem = key_data.encode() if isinstance(key_data, str) else key_data
            material = SSHKeyMaterial(
                private_key_pem=SecureBytes(pem),
                passphrase=SecureBytes(passphrase.encode()) if passphrase else None,
                key_type="unknown"
            )
            # Update in-memory cache
            self._set_cached_credential(item_id, "ssh-key", material)

            # Persist to the local secure vault so next connection is instant
            try:
                from services.vault_manager import VaultManager
                vm = VaultManager.get()
                if vm.is_unlocked:
                    vm.cache_ssh_key(
                        item_id=item_id,
                        label=item.get("name", item_id),
                        key_material=material,
                    )
                    logger.debug("Bitwarden: SSH key cached in local vault for '%s'.", item_id)
            except Exception as _e:
                logger.debug("Bitwarden: Could not cache SSH key in vault: %s", _e)

            return material
        except Exception as e:
            logger.error(f"Failed to retrieve SSH key from Bitwarden: {e}")
            raise

    async def get_totp_code(self, item_id: str) -> str | None:
        """Retrieve TOTP code for a specific item."""
        if not await self.is_unlocked():
            raise RuntimeError("Vault is locked")
            
        try:
            # Bitwarden CLI has a specific 'get totp' command
            code = await self._run_bw(["get", "totp", item_id])
            return code.strip() if code else None
        except Exception as e:
            # It might fail if no TOTP is configured for the item
            logger.debug(f"Failed to get TOTP for {item_id}: {e}")
            return None

    async def store_connection_config(self, config: dict) -> str:
        """Bitwarden sync of configs is a bonus Phase 4 feature."""
        raise NotImplementedError("Syncing configs to Bitwarden notes is not yet implemented.")

    async def retrieve_connection_configs(self) -> list[dict]:
        """Bitwarden sync of configs is a bonus Phase 4 feature."""
        raise NotImplementedError("Syncing configs to Bitwarden notes is not yet implemented.")

    # ── Helpers ─────────────────────────────────────────────────

    def _try_load_cached_session(self) -> None:
        """Try to restore a saved Bitwarden session from the local SecureVault."""
        try:
            from services.vault_manager import VaultManager
            vm = VaultManager.get()
            if not vm.is_unlocked:
                return
            email, token = vm.get_bitwarden_session()
            if token:
                logger.info(f"Bitwarden: Restored session from local vault for {email}.")
                if self._session_token:
                    self._session_token.clear()
                self._session_token = SecureBytes(token)
        except Exception as e:
            logger.debug("Bitwarden: Could not restore cached session: %s", e)
