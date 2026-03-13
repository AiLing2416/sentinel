# SPDX-License-Identifier: GPL-3.0-or-later

"""SSH connection service — manages sessions via AsyncEngine and asyncssh.

This service initializes connections and delegates process execution to 
SessionBridge. Passwords and interactive callbacks are handled securely.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import datetime
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Any, Sequence
from enum import Enum

import asyncssh

from models.connection import AuthMethod, Connection
from services.async_engine import call_ui_async, call_ui_sync, AsyncEngine
from utils.secure import SecureBytes
from db.database import Database
from services.ssh_client import SentinelSSHClient, SessionBridge

logger = logging.getLogger(__name__)

# asyncssh logging is handled by the application's global log level.
# We explicitly set it to WARNING here to avoid noise in the console.
asyncssh.set_log_level(logging.WARNING)


@dataclass
class LocalCommand:
    """A validated, ready-to-spawn local command."""
    argv: list[str]
    display_label: str = "Local Shell"

class SessionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"

@dataclass
class SessionInfo:
    connection_id: str
    state: SessionState
    pid: int | None = None
    started_at: float | None = None
    error: str | None = None


class BoundClient(SentinelSSHClient):
    """Internal client that tracks new host keys for the verification loop."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_key: asyncssh.SSHKey | None = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: asyncssh.SSHKey) -> bool:
        db = Database()
        db.open()
        try:
            fp = key.get_fingerprint()
            alg = key.get_algorithm()
            row = db._conn.execute(
                "SELECT trusted FROM known_hosts "
                "WHERE hostname=? AND port=? AND fingerprint=? AND key_type=?",
                (host, port, fp, alg)
            ).fetchone()
            if row and row[0]:
                return True
            self.server_key = key
            return False
        finally:
            db.close()


class SSHService:
    """Connects to SSH servers using asyncssh, bridging I/O to GTK UI."""

    def __init__(self) -> None:
        self.engine = AsyncEngine.get()
        self.engine.start()
        self._sessions: dict[str, SessionInfo] = {}

    def build_local_shell_command(self) -> LocalCommand:
        """Build a command for a local shell tab."""
        shell = shutil.which("bash") or shutil.which("sh") or "/bin/sh"
        return LocalCommand(argv=[shell])

    async def _get_connection_by_id(self, conn_id: str) -> Connection | None:
        """Fetch connection from database by ID."""
        db = Database()
        db.open()
        try:
            return db.get_connection(conn_id)
        finally:
            db.close()

    async def connect_and_start_session(
        self,
        conn: Connection,
        ui_callbacks: dict[str, Callable],
        output_cb: Callable[[bytes], None],
        exit_cb: Callable[[int], None],
        status_cb: Callable[[str], None] | None = None,
        _tunnel: Any = None,
        _depth: int = 0
    ) -> Any:
        """Establish asyncssh connection and start a PTY process."""
        if _depth > 5:
            raise ValueError("ProxyJump recursion limit reached (max 5 jumps)")

        def set_status(msg: str):
            if status_cb:
                call_ui_sync(status_cb, msg)
        
        try:
            # Load keys if provided (KEY / KEY_PASSPHRASE auth only)
            _loaded_keys: list = []
            if conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE) and conn.key_path:
                set_status("Loading local keys...")
                key_path = Path(conn.key_path).expanduser()
                async def ask_passphrase() -> SecureBytes:
                    pw = await call_ui_async(ui_callbacks["ask_passphrase"], str(key_path))
                    if pw is None:
                        raise asyncio.CancelledError("User cancelled passphrase input")
                    return pw
                    
                try:
                    keys = asyncssh.read_private_key(key_path)
                    _loaded_keys.append(keys)
                except asyncssh.KeyImportError as e:
                    logger.info(f"Key import needs passphrase: {e}")
                    pwd = await ask_passphrase()
                    try:
                        # asyncssh.read_private_key accepts bytes-like for passphrase
                        keys = asyncssh.read_private_key(key_path, pwd.get_view())
                        _loaded_keys.append(keys)
                    except Exception as final_e:
                        raise ValueError(f"AuthenticationFailedError: {final_e}") from None
                    finally:
                        pwd.clear()

            # Connection parameters
            kwargs: dict[str, Any] = {
                "host": conn.hostname,
                "port": conn.port,
                "username": conn.username or None,
                "client_keys": None,
                "known_hosts": b"# sentinel managed\n",
                "connect_timeout": 30,
                "gss_auth": False,
                "agent_path": None, # Explicitly disable agent to prevent background hangs
                "agent_forwarding": conn.agent_forwarding,
                "keepalive_interval": 60,
                "keepalive_count_max": 3,
                "tunnel": _tunnel,
            }

            # ── Jump Host setup ─────────────────────────────────────────
            if conn.jump_host_id and not _tunnel:
                jump_conn = await self._get_connection_by_id(conn.jump_host_id)
                if jump_conn:
                    set_status(f"Connecting to jump host: {jump_conn.display_name or jump_conn.hostname}…")
                    # Recursive call to get the tunnel connection
                    # Note: We don't start a session on the jump host, just establish connection
                    jump_ssh_conn, _ = await self.connect_and_start_session(
                        jump_conn, ui_callbacks, lambda x: None, lambda x: None, 
                        status_cb=status_cb, _depth=_depth + 1
                    )
                    kwargs["tunnel"] = jump_ssh_conn
                else:
                    logger.warning(f"Jump host ID {conn.jump_host_id} not found in database.")

            # ── Auth setup ─────────────────────────────────────────
            password_provider: Any = None

            if conn.auth_method == AuthMethod.PASSWORD:
                set_status("Waiting for password…")
                pw = await call_ui_async(ui_callbacks["ask_password"], conn)
                if pw is None:
                    logger.info("User cancelled password input.")
                    raise asyncio.CancelledError("User cancelled password input")
                
                _pwd_str = pw.unsafe_get_str()
                kwargs["password"] = _pwd_str
                password_provider = lambda: _pwd_str
                # We can't clear pw yet if password_provider is used later
                # so we let GC handle it or clear it after connect.
                # Note: asyncssh usually requires a string for password.
                kwargs["preferred_auth"] = ["password", "keyboard-interactive"]

            elif conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE):
                if _loaded_keys:
                    kwargs["client_keys"] = _loaded_keys

            elif conn.auth_method == AuthMethod.AGENT:
                del kwargs["client_keys"]
                kwargs["agent_path"] = True # Re-enable auto detection

            elif conn.auth_method == AuthMethod.VAULT:
                from services.vault_service import VaultService
                vs = VaultService.get()
                vault = vs.active_backend
                if not vault:
                    return

                if not await vault.is_unlocked():
                    set_status(f"Unlocking {vault.name}...")
                    unlocked = await call_ui_async(ui_callbacks["ask_vault_unlock"], vault.name)
                    if not unlocked:
                        raise asyncio.CancelledError("User cancelled vault unlock")
                
                set_status(f"Searching {vault.name}...")
                item_id = conn.vault_item_id
                if not item_id:
                    found = await vault.search_credentials(conn.hostname, conn.username)
                    if not found:
                        raise ValueError("No matching credentials found in vault")
                    elif len(found) == 1:
                        item_id = found[0].item_id
                    else:
                        item_id = await call_ui_async(ui_callbacks["ask_vault_item"], found)
                        if not item_id:
                            raise asyncio.CancelledError("User cancelled vault item selection")

                set_status("Retrieving credentials...")
                try:
                    try:
                        key_material = await vault.get_ssh_key(item_id)
                        # import_private_key accepts bytes-like, so memoryview works
                        private_key = asyncssh.import_private_key(
                            key_material.private_key_pem.get_view(),
                            key_material.passphrase.get_view() if key_material.passphrase else None
                        )
                        kwargs["client_keys"] = [private_key]
                        # Material is in key_material (SecureBytes), will clear on GC
                        # but we can't manually clear it yet because asyncssh might 
                        # have a reference to the buffer if it didn't copy it.
                        # However, asyncssh usually parses PEM into internal structures.
                    except Exception:
                        if hasattr(vault, 'get_password'):
                            pwd = await vault.get_password(item_id)
                            # Passing view to password/provider if asyncssh supports bytes-like
                            # If not, we use the string but clear it soon.
                            _v_pwd = pwd.unsafe_get_str()
                            pwd.clear()
                            kwargs["password"] = _v_pwd
                            password_provider = lambda: _v_pwd
                            kwargs["preferred_auth"] = ["password", "keyboard-interactive"]
                        
                        # Add TOTP provider if supported by backend
                        if hasattr(vault, 'get_totp_code'):
                            kwargs["totp_provider"] = lambda: vault.get_totp_code(item_id)

                except Exception as e:
                    logger.error(f"Vault retrieval failed: {e}")
                    raise

            client_instance: BoundClient | None = None

            def client_factory() -> BoundClient:
                nonlocal client_instance
                client_instance = BoundClient(
                    conn, ui_callbacks, 
                    password_provider=password_provider,
                    totp_provider=kwargs.get("totp_provider")
                )
                return client_instance
            
            kwargs["client_factory"] = client_factory

            while True:
                try:
                    set_status(f"Handshaking with {conn.hostname}...")
                    logger.debug(f"Calling asyncssh.connect for {conn.hostname}...")
                    connection = await asyncssh.connect(**kwargs)
                    set_status("Connected! Initializing shell...")
                    logger.info(f"Connected to {conn.hostname}!")
                    break
                except (Exception, asyncio.CancelledError) as e:
                    # Clean up tunnel if handshake fails
                    if kwargs.get("tunnel"):
                        kwargs["tunnel"].close()
                        await kwargs["tunnel"].wait_closed()

                    if client_instance and client_instance.server_key:
                        k = client_instance.server_key
                        accepted = await call_ui_async(
                            ui_callbacks["ask_host_key"], conn.hostname, k.get_fingerprint(), k.get_algorithm()
                        )
                        if accepted:
                            db = Database()
                            db.open()
                            try:
                                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                                db._conn.execute(
                                    "INSERT OR REPLACE INTO known_hosts (hostname, port, key_type, fingerprint, first_seen, last_seen, trusted) VALUES (?, ?, ?, ?, ?, ?, 1)",
                                    (conn.hostname, conn.port, k.get_algorithm(), k.get_fingerprint(), now, now)
                                )
                                db._conn.commit()
                            finally:
                                db.close()
                            client_instance.server_key = None
                            continue
                        else:
                            raise asyncio.CancelledError("Host key verification rejected")
                        
                    # Re-raise to be caught by outer handler
                    raise e

            # Return connection if we are just tunneling
            if _depth > 0:
                return connection, None
        except asyncio.CancelledError:
            if "on_cancelled" in ui_callbacks:
                call_ui_sync(ui_callbacks["on_cancelled"])
            return
        except Exception as e:
            if isinstance(e, asyncssh.PermissionDenied):
                call_ui_sync(ui_callbacks["on_error"], f"Authentication failed: {e}")
            else:
                call_ui_sync(ui_callbacks["on_error"], f"Connection failed: {e}")
            return


        session = await connection.create_process(
            term_type="xterm-256color",
            request_pty="force",
            encoding=None,
        )
        
        bridge = SessionBridge(session, output_cb, exit_cb)
        bridge._conn_ref = connection 
        call_ui_sync(ui_callbacks["on_connected"], bridge)
        
        # Apply Port Forwarding rules
        await self._apply_forward_rules(connection, conn.id)
        
        # Background tasks...
        async def background_tasks():
            # Sync vault
            if conn.auth_method == AuthMethod.VAULT:
                try:
                    vs = VaultService.get()
                    if hasattr(vs.active_backend, 'sync'):
                        await vs.active_backend.sync()
                except Exception: pass
            
            # Detect OS
            if not conn.os_id:
                try:
                    res = await connection.run("cat /etc/os-release", check=False)
                    if res.exit_status == 0 and res.stdout:
                        import re
                        match = re.search(r'^ID=[\'\"]?([a-zA-Z0-9_\-]+)[\'\"]?', res.stdout, re.MULTILINE)
                        if match:
                            os_id = match.group(1).lower()
                            conn.os_id = os_id
                            db = Database()
                            db.open()
                            try:
                                db.save_connection(conn)
                                if "on_os_detected" in ui_callbacks:
                                    call_ui_sync(ui_callbacks["on_os_detected"], conn.id, os_id)
                            finally:
                                db.close()
                except Exception: pass

        asyncio.create_task(background_tasks())
        await bridge.run()

    async def start_sftp_session(
        self,
        conn: Connection,
        ui_callbacks: dict[str, Callable],
        status_cb: Callable[[str], None] | None = None,
    ) -> Any:
        """Establish asyncssh connection and return an SFTPClient."""
        def set_status(msg: str):
            if status_cb:
                call_ui_sync(status_cb, msg)
        
        try:
            # Re-use most of the logic from connect_and_start_session
            # But we only need the connection object
            
            # (Copied auth logic - maybe refactor later)
            _loaded_keys: list = []
            if conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE) and conn.key_path:
                set_status("Loading local keys...")
                key_path = Path(conn.key_path).expanduser()
                async def ask_passphrase() -> SecureBytes:
                    pw = await call_ui_async(ui_callbacks["ask_passphrase"], str(key_path))
                    if pw is None:
                        raise asyncio.CancelledError("User cancelled passphrase input")
                    return pw
                    
                try:
                    keys = asyncssh.read_private_key(key_path)
                    _loaded_keys.append(keys)
                except asyncssh.KeyImportError as e:
                    logger.info(f"Key import needs passphrase: {e}")
                    pwd = await ask_passphrase()
                    try:
                        keys = asyncssh.read_private_key(key_path, pwd.get_view())
                        _loaded_keys.append(keys)
                        # We will set auth_info["key_passphrase"] later
                        _key_pass_sb = pwd
                    except Exception as final_e:
                        pwd.clear()
                        raise ValueError(f"AuthenticationFailedError: {final_e}") from None
                    # Do NOT clear pwd here, it's saved in _key_pass_sb

            kwargs: dict[str, Any] = {
                "host": conn.hostname,
                "port": conn.port,
                "username": conn.username or None,
                "client_keys": None,
                "known_hosts": b"# sentinel managed\n",
                "connect_timeout": 30,
                "gss_auth": False,
                "agent_path": None,
            }

            auth_info: dict[str, Any] = {}
            
            password_provider: Any = None
            if conn.auth_method == AuthMethod.PASSWORD:
                set_status("Waiting for password…")
                pw = await call_ui_async(ui_callbacks["ask_password"], conn)
                if pw is None:
                    raise asyncio.CancelledError("User cancelled password input")
                _pwd_str = pw.unsafe_get_str()
                kwargs["password"] = _pwd_str
                auth_info["password"] = pw  # Store SecureBytes directly
                password_provider = lambda: _pwd_str
                # Note: asyncssh usually requires a string for password.
                kwargs["preferred_auth"] = ["password", "keyboard-interactive"]
            elif conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE):
                if _loaded_keys:
                    kwargs["client_keys"] = _loaded_keys
                    auth_info["key_path"] = str(key_path)
                    if '_key_pass_sb' in locals():
                         auth_info["key_passphrase"] = _key_pass_sb
            elif conn.auth_method == AuthMethod.AGENT:
                del kwargs["client_keys"]
                kwargs["agent_path"] = True
            elif conn.auth_method == AuthMethod.VAULT:
                from services.vault_service import VaultService
                vs = VaultService.get()
                vault = vs.active_backend
                if not vault: return None
                if not await vault.is_unlocked():
                    unlocked = await call_ui_async(ui_callbacks["ask_vault_unlock"], vault.name)
                    if not unlocked: raise asyncio.CancelledError("User cancelled vault unlock")
                item_id = conn.vault_item_id
                if not item_id:
                    found = await vault.search_credentials(conn.hostname, conn.username)
                    if not found: raise ValueError("No matching credentials found in vault")
                    elif len(found) == 1: item_id = found[0].item_id
                    else:
                        item_id = await call_ui_async(ui_callbacks["ask_vault_item"], found)
                        if not item_id: raise asyncio.CancelledError("User cancelled vault item selection")
                try:
                    try:
                        key_material = await vault.get_ssh_key(item_id)
                        # import_private_key accepts bytes-like
                        private_key = asyncssh.import_private_key(
                            key_material.private_key_pem.get_view(),
                            key_material.passphrase.get_view() if key_material.passphrase else None
                        )
                        kwargs["client_keys"] = [private_key]
                        
                        auth_info["private_key_pem"] = key_material.private_key_pem
                        if key_material.passphrase:
                             auth_info["key_passphrase"] = key_material.passphrase
                    except Exception:
                        if hasattr(vault, 'get_password'):
                            pwd = await vault.get_password(item_id)
                            _v_pwd = pwd.unsafe_get_str()
                            kwargs["password"] = _v_pwd
                            auth_info["password"] = pwd
                            password_provider = lambda: _v_pwd
                            kwargs["preferred_auth"] = ["password", "keyboard-interactive"]
                except Exception as e:
                    logger.error(f"Vault retrieval failed: {e}")
                    raise

            client_instance: BoundClient | None = None
            def client_factory() -> BoundClient:
                nonlocal client_instance
                client_instance = BoundClient(conn, ui_callbacks, password_provider=password_provider)
                return client_instance
            kwargs["client_factory"] = client_factory

            while True:
                try:
                    set_status(f"Handshaking with {conn.hostname}...")
                    connection = await asyncssh.connect(**kwargs)
                    set_status("Connected! Opening SFTP...")
                    break
                except (Exception, asyncio.CancelledError) as e:
                    if client_instance and client_instance.server_key:
                        k = client_instance.server_key
                        accepted = await call_ui_async(
                            ui_callbacks["ask_host_key"], conn.hostname, k.get_fingerprint(), k.get_algorithm()
                        )
                        if accepted:
                            db = Database()
                            db.open()
                            try:
                                now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                                db._conn.execute(
                                    "INSERT OR REPLACE INTO known_hosts (hostname, port, key_type, fingerprint, first_seen, last_seen, trusted) VALUES (?, ?, ?, ?, ?, ?, 1)",
                                    (conn.hostname, conn.port, k.get_algorithm(), k.get_fingerprint(), now, now)
                                )
                                db._conn.commit()
                            finally: db.close()
                            client_instance.server_key = None
                            continue
                        else: raise asyncio.CancelledError("Host key verification rejected")
                    raise e
            
            sftp = await connection.start_sftp_client()
            return sftp, connection, auth_info
            
        except asyncio.CancelledError:
            if "on_cancelled" in ui_callbacks:
                call_ui_sync(ui_callbacks["on_cancelled"])
            return None
        except Exception as e:
            if isinstance(e, asyncssh.PermissionDenied):
                call_ui_sync(ui_callbacks["on_error"], f"Authentication failed: {e}")
            else:
                call_ui_sync(ui_callbacks["on_error"], f"Connection failed: {e}")
            return None

    # --- Session Management ---
    def register_session(self, conn_id: str) -> SessionInfo:
        self._sessions[conn_id] = SessionInfo(conn_id, SessionState.CONNECTING, started_at=time.time())
        return self._sessions[conn_id]

    async def _apply_forward_rules(self, connection: asyncssh.SSHClientConnection, connection_id: str) -> None:
        """Read forward rules from DB and apply them to the established connection."""
        from models.forward_rule import ForwardRule, ForwardType
        db = Database()
        db.open()
        try:
            rows = db._conn.execute(
                "SELECT * FROM forward_rules WHERE connection_id = ? AND enabled = 1",
                (connection_id,)
            ).fetchall()
            rules = [ForwardRule.from_dict(dict(r)) for r in rows]
        finally:
            db.close()

        for rule in rules:
            try:
                if rule.type == ForwardType.LOCAL:
                    await connection.start_local_forward(
                        rule.bind_address, rule.bind_port,
                        rule.remote_host, rule.remote_port
                    )
                    logger.info(f"Local forward started: {rule.bind_address}:{rule.bind_port} -> {rule.remote_host}:{rule.remote_port}")
                elif rule.type == ForwardType.REMOTE:
                    await connection.start_remote_forward(
                        rule.bind_address, rule.bind_port,
                        rule.remote_host, rule.remote_port
                    )
                    logger.info(f"Remote forward started: {rule.bind_address}:{rule.bind_port} -> {rule.remote_host}:{rule.remote_port}")
                elif rule.type == ForwardType.DYNAMIC:
                    await connection.start_dynamic_forward(
                        rule.bind_address, rule.bind_port
                    )
                    logger.info(f"Dynamic (SOCKS) forward started: {rule.bind_address}:{rule.bind_port}")
            except Exception as e:
                logger.error(f"Failed to apply forward rule {rule.id}: {e}")

    def update_session_state(self, conn_id: str, state: SessionState, pid: int | None = None, error: str | None = None) -> None:
        if conn_id in self._sessions:
            self._sessions[conn_id].state = state
            if pid: self._sessions[conn_id].pid = pid
            if error: self._sessions[conn_id].error = error

    def get_session(self, conn_id: str) -> SessionInfo | None:
        return self._sessions.get(conn_id)

    def remove_session(self, conn_id: str) -> None:
        self._sessions.pop(conn_id, None)

    @property
    def active_sessions(self) -> dict[str, SessionInfo]:
        return {k: v for k, v in self._sessions.items() if v.state in (SessionState.CONNECTING, SessionState.CONNECTED)}


# --- Internal Helper Classes ---

from services.ssh_client import SentinelSSHClient

class BoundClient(SentinelSSHClient):
    """Internal client that tracks new host keys for the verification loop."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server_key: asyncssh.SSHKey | None = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: asyncssh.SSHKey) -> bool:
        db = Database()
        db.open()
        try:
            fp = key.get_fingerprint()
            alg = key.get_algorithm()
            row = db._conn.execute(
                "SELECT trusted FROM known_hosts "
                "WHERE hostname=? AND port=? AND fingerprint=? AND key_type=?",
                (host, port, fp, alg)
            ).fetchone()
            if row and row[0]:
                return True
            self.server_key = key
            return False
        finally:
            db.close()
