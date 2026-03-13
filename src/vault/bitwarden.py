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
        self._auto_synced = False
        self._last_folders: list[dict[str, str]] = []
        
        # In-memory cache for retrieved credentials (passwords/keys)
        # item_id -> { "password": SecureBytes, "ssh-key": SSHKeyMaterial }
        self._item_cache: dict[str, dict[str, Any]] = {}
        
        # Performance: Cache the unlocked status for 30 seconds to avoid repeating 'bw status'
        self._status_cache: bool | None = None
        self._status_cache_time: float = 0
        
        # Log version for debugging (manual verification done, keeping it simple)
        # No explicit version check here, relying on 'bw' to be functional.

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

        env = os.environ.copy()
        if self._session_token:
            # Environment variables must be strings, so we use unsafe_get_str().
            # Bitwarden CLI relies on this env var for authentication.
            env["BW_SESSION"] = self._session_token.unsafe_get_str()
        else:
            # Mask sensitive commands
            safe_args = list(args)
            if safe_args and safe_args[0] in ["unlock", "login"]:
                safe_args = [safe_args[0], "**** (masked)"]
            logger.debug(f"Bitwarden: Running '{' '.join(safe_args)}' WITHOUT session token.")

        process = await asyncio.create_subprocess_exec(
            self._cli_path,
            *args,
            stdin=asyncio.subprocess.PIPE if input_str else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await process.communicate(
            input=input_str.encode() if input_str else None
        )

        if process.returncode != 0:
            err_msg = stderr.decode().strip()
            logger.error(f"Bitwarden CLI error: {err_msg}")
            raise RuntimeError(f"Bitwarden CLI failed: {err_msg}")

        return stdout

    async def login(self, email: str, password: SecureBytes | str, method: int | None = None, code: SecureBytes | str | None = None) -> bool:
        """Log in to Bitwarden securely. Password passed via stdin."""
        try:
            args = ["login", email, "--raw", "--nointeraction"]
            if method is not None:
                args.extend(["--method", str(method)])
            if code:
                _code = code.unsafe_get_str() if isinstance(code, SecureBytes) else code
                args.extend(["--code", _code])
                
            pwd_input = password.get_view() if isinstance(password, SecureBytes) else password.encode()
            
            process = await asyncio.create_subprocess_exec(
                self._cli_path,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await process.communicate(input=pwd_input)
            
            if process.returncode != 0:
                err_msg = stderr.decode().strip()
                # Re-raise to let UI handle 2FA detection or other errors
                raise RuntimeError(err_msg)
                
            token = stdout.decode().strip()
            if token:
                if self._session_token:
                    self._session_token.clear()
                self._session_token = SecureBytes(token)
                return True
            return False
        except Exception as e:
            logger.error(f"Bitwarden login failed: {e}")
            raise

    async def unlock(self, master_password: SecureBytes | str) -> bool:
        """Unlock the vault and store the session token.
        Master password is passed via stdin to avoid ps leakage.
        """
        try:
            # First check status
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)

            if status.get("status") == "unauthenticated":
                logger.warning("Bitwarden is not logged in.")
                return False

            # Prepare password input
            pwd_input = master_password.get_view() if isinstance(master_password, SecureBytes) else master_password.encode()
            
            # Use --raw to get only the token on stdout
            process = await asyncio.create_subprocess_exec(
                self._cli_path,
                "unlock", "--raw",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate(input=pwd_input)

            if process.returncode != 0:
                err_msg = stderr.decode().strip()
                logger.error(f"Bitwarden unlock failed: {err_msg}")
                return False

            token = stdout.decode().strip()
            if token:
                if self._session_token:
                    self._session_token.clear()
                self._session_token = SecureBytes(token)
                
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to unlock Bitwarden: {e}")
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
            
        self._item_cache.clear()

    async def is_unlocked(self) -> bool:
        """Check if the vault is unlocked. Uses a 30s cache to keep UI responsive."""
        import time
        now = time.time()
        
        if self._status_cache is not None and (now - self._status_cache_time) < 30:
            return self._status_cache

        if not self._session_token:
            self._status_cache = False
            return False

        if not self._session_token:
            self._status_cache = False
            return False

        try:
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)
            state = status.get("status")
            unlocked = (state == "unlocked")
            
            if not unlocked:
                 # If we have a token but CLI says locked, the token might be dead
                 self._session_token.clear()
                 self._session_token = None
                 self._item_cache.clear()
            
            self._status_cache = unlocked
            self._status_cache_time = now
            return unlocked
        except Exception:
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
        try:
            status_raw = await self._run_bw(["status"])
            status = json.loads(status_raw)
            return status.get("serverUrl")
        except Exception:
            return None

    async def get_password(self, item_id: str) -> SecureBytes:
        """Retrieve password. Tries Keyring cache first."""
        cached = self._get_cached_credential(item_id, "password")
        if cached:
            logger.debug(f"Password for {item_id} hit memory cache.")
            return cached

        if not await self.is_unlocked():
            raise RuntimeError("Vault is locked")
            
        try:
            item_raw = await self._run_bw(["get", "item", item_id])
            item = json.loads(item_raw)
            password = item.get("login", {}).get("password")
            if not password:
                raise ValueError("No password found in item")
            
            # 2. Update Cache
            sb = SecureBytes(password)
            self._set_cached_credential(item_id, "password", sb)
            return sb
        except Exception as e:
            logger.error(f"Failed to retrieve password from Bitwarden: {e}")
            raise

    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial:
        """Retrieve SSH key material. Tries Keyring cache first."""
        cached_key = self._get_cached_credential(item_id, "ssh-key")
        if cached_key:
            logger.debug(f"SSH Key for {item_id} hit memory cache.")
            return cached_key

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
                for att in attachments:
                    fn = att.get("fileName", "").lower()
                    if fn in ["id_rsa", "id_ed25519", "id_ecdsa"] or fn.endswith(".pem") or fn.endswith(".key") or "ssh" in fn:
                         try:
                            key_data = await self._run_bw_raw(["get", "attachment", att["id"], "--itemid", item_id])
                            break
                         except Exception: pass

            # 4. Fallback to notes
            if not key_data:
                notes = item.get("notes", "")
                if "-----BEGIN" in notes:
                    key_data = notes

            if not key_data:
                raise ValueError("No SSH key found in Bitwarden item")

            # Update cache for next time
            pem = key_data.encode() if isinstance(key_data, str) else key_data
            material = SSHKeyMaterial(
                private_key_pem=SecureBytes(pem),
                passphrase=SecureBytes(passphrase.encode()) if passphrase else None,
                key_type="unknown"
            )
            self._set_cached_credential(item_id, "ssh-key", material)
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
