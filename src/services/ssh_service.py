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
from typing import Callable, Any, Sequence, cast
from enum import Enum

import asyncssh

from models.connection import AuthMethod, Connection
from models.forward_rule import ForwardRule, ForwardType
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
        self._active_ssh_connections: dict[str, list[asyncssh.SSHClientConnection]] = {}
        self._active_listeners: dict[str, tuple[asyncssh.SSHListener, asyncssh.SSHClientConnection]] = {}
        self._rule_errors: dict[str, str] = {}
        self._forward_rules_listeners: list[Callable[[], None]] = []

    def build_local_shell_command(self) -> LocalCommand:
        """Build a command for a local shell tab. 
        Detects if running inside Flatpak and uses host spawner if needed.
        """
        import os
        is_flatpak = os.path.exists("/.flatpak-info")
        
        if is_flatpak:
            spawn_host = shutil.which("flatpak-spawn") or "/usr/bin/flatpak-spawn"
            return LocalCommand(
                argv=[spawn_host, "--host", "--env=TERM=xterm-256color", "bash", "--login"], 
                display_label="Host Shell"
            )
            
        shell = shutil.which("bash") or shutil.which("sh") or "/bin/sh"
        return LocalCommand(argv=[shell, "-l"])

    async def start_local_session(
        self,
        local_cmd: LocalCommand,
        ui_callbacks: dict[str, Callable],
        output_cb: Callable[[bytes], None],
        exit_cb: Callable[[int], None]
    ) -> Any:
        """Spawn a local process and bridge it using PTY for full TUI support."""
        import os, pty, termios, struct, fcntl
        
        master_fd, slave_fd = pty.openpty()
        
        try:
            async def pty_reader():
                loop = asyncio.get_running_loop()
                while True:
                    try:
                        data = await loop.run_in_executor(None, os.read, master_fd, 4096)
                        if not data:
                            break
                        call_ui_sync(output_cb, data)
                    except OSError:
                        break
                call_ui_sync(exit_cb, 0)
            
            process = await asyncio.create_subprocess_exec(
                *local_cmd.argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid,
                env=os.environ.copy()
            )
            
            os.close(slave_fd)
            
            class LocalBridge:
                def __init__(self, proc, master):
                    self.process = proc
                    self.master_fd = master
                    
                def write(self, data: bytes):
                    try: os.write(self.master_fd, data)
                    except: pass
                    
                def resize(self, columns: int, rows: int):
                    try:
                        s = struct.pack('HHHH', rows, columns, 0, 0)
                        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, s)
                    except: pass
                    
                def close(self):
                    try:
                        self.process.terminate()
                        os.close(self.master_fd)
                    except: pass

            bridge = LocalBridge(process, master_fd)
            asyncio.create_task(pty_reader())
            
            call_ui_sync(ui_callbacks["on_connected"], bridge)
            return bridge

        except Exception as e:
            logger.error(f"Failed to start local session: {e}")
            call_ui_sync(ui_callbacks["on_error"], str(e))
            return None

    async def _get_connection_by_id(self, conn_id: str) -> Connection | None:
        """Fetch connection from database by ID."""
        db = Database()
        db.open()
        try:
            return db.get_connection(conn_id)
        finally:
            db.close()

    async def _establish_connection(
        self,
        conn: Connection,
        ui_callbacks: dict[str, Callable],
        status_cb: Callable[[str], None] | None = None,
        _tunnel: Any = None,
        _depth: int = 0
    ) -> tuple[asyncssh.SSHClientConnection, dict[str, Any], BoundClient] | None:
        """Core connection logic shared between Shell and SFTP."""
        if _depth > 5:
            raise ValueError("ProxyJump recursion limit reached (max 5 jumps)")

        def set_status(msg: str):
            if status_cb:
                call_ui_sync(status_cb, msg)
        
        try:
            auth_info: dict[str, Any] = {}
            _loaded_keys: list = []
            
            # 1. Key Loading
            if conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE) and conn.key_path:
                set_status("Loading local keys...")
                key_path = Path(conn.key_path).expanduser()
                auth_info["key_path"] = str(key_path)
                
                async def ask_passphrase() -> SecureBytes:
                    pw = await call_ui_async(ui_callbacks["ask_passphrase"], str(key_path))
                    if pw is None: raise asyncio.CancelledError("User cancelled passphrase input")
                    return pw
                    
                try:
                    keys = asyncssh.read_private_key(key_path)
                    _loaded_keys.append(keys)
                except asyncssh.KeyImportError:
                    pwd = await ask_passphrase()
                    try:
                        keys = asyncssh.read_private_key(key_path, pwd.get_view())
                        _loaded_keys.append(keys)
                        auth_info["key_passphrase"] = pwd
                    except Exception as final_e:
                        pwd.clear()
                        raise ValueError(f"AuthenticationFailedError: {final_e}") from None

            # 2. Base Kwargs
            kwargs: dict[str, Any] = {
                "host": conn.hostname,
                "port": conn.port,
                "username": conn.username or None,
                "client_keys": [],
                "known_hosts": b"# sentinel managed\n",
                "connect_timeout": 30,
                "gss_auth": False,
                "agent_path": None,
                "keepalive_interval": 60,
                "keepalive_count_max": 3,
                "tunnel": _tunnel,
            }

            # 3. Auth Setup
            password_provider: Any = None
            if conn.auth_method == AuthMethod.PASSWORD:
                from services.vault_manager import VaultManager
                pw = VaultManager.get().get_cached_password(conn.id)
                if pw is None:
                    set_status("Waiting for password...")
                    pw = await call_ui_async(ui_callbacks["ask_password"], conn)

                if pw is None: raise asyncio.CancelledError("User cancelled password input")
                
                auth_info["password"] = pw
                _pwd_ba = bytearray(pw.get_view())
                kwargs["password"] = _pwd_ba
                password_provider = lambda: _pwd_ba
                kwargs["preferred_auth"] = ["password", "keyboard-interactive"]

            elif conn.auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE):
                if _loaded_keys: kwargs["client_keys"] = _loaded_keys

            elif conn.auth_method == AuthMethod.AGENT:
                del kwargs["client_keys"]
                kwargs["agent_path"] = True

            elif conn.auth_method == AuthMethod.VAULT:
                from services.vault_service import VaultService
                vs = VaultService.get()
                vault = vs.active_backend
                if not vault: return None

                if not await vault.is_unlocked():
                    set_status(f"Unlocking {vault.name}...")
                    unlocked = await call_ui_async(ui_callbacks["ask_vault_unlock"], vault.name)
                    if not unlocked: raise asyncio.CancelledError("User cancelled vault unlock")
                
                set_status(f"Searching {vault.name}...")
                item_id = conn.vault_item_id
                if not item_id:
                    found = await vault.search_credentials(conn.hostname, conn.username)
                    if not found: raise ValueError("No matching credentials found in vault")
                    elif len(found) == 1: item_id = found[0].item_id
                    else:
                        item_id = await call_ui_async(ui_callbacks["ask_vault_item"], found)
                        if not item_id: raise asyncio.CancelledError("User cancelled vault item selection")

                set_status("Retrieving credentials...")
                try:
                    try:
                        key_material = await vault.get_ssh_key(item_id)
                        pem_ba = bytearray(key_material.private_key_pem.get_view())
                        pass_ba = bytearray(key_material.passphrase.get_view()) if key_material.passphrase else None
                        try:
                            private_key = asyncssh.import_private_key(pem_ba, pass_ba)
                            kwargs["client_keys"] = [private_key]
                            auth_info["private_key_pem"] = key_material.private_key_pem
                            if key_material.passphrase: auth_info["key_passphrase"] = key_material.passphrase
                        finally:
                            for b in range(len(pem_ba)): pem_ba[b] = 0
                            if pass_ba:
                                for b in range(len(pass_ba)): pass_ba[b] = 0
                    except ValueError:
                        if hasattr(vault, 'get_password'):
                            pwd = await vault.get_password(item_id)
                            auth_info["password"] = pwd
                            _v_pwd_ba = bytearray(pwd.get_view())
                            kwargs["password"] = _v_pwd_ba
                            password_provider = lambda: _v_pwd_ba
                            kwargs["preferred_auth"] = ["password", "keyboard-interactive"]
                    except asyncssh.KeyImportError as ki_err:
                        raise ValueError(f"SSH key found but failed to import: {ki_err}") from None
                except Exception as e:
                    logger.error(f"Vault retrieval failed: {e}")
                    raise

            totp_provider: Any = None
            if conn.auth_method == AuthMethod.VAULT and hasattr(vault, 'get_totp_code'):
                totp_provider = lambda: vault.get_totp_code(item_id)

            client_instance: BoundClient | None = None
            def client_factory() -> BoundClient:
                nonlocal client_instance
                client_instance = BoundClient(conn, ui_callbacks, password_provider=password_provider, totp_provider=totp_provider)
                return client_instance
            kwargs["client_factory"] = client_factory

            # 4. Connect Loop
            while True:
                try:
                    set_status(f"Handshaking with {conn.hostname}...")
                    connection = await asyncssh.connect(**kwargs)
                    self._register_ssh_connection(conn.id, connection)
                    return connection, auth_info, client_instance
                except (Exception, asyncio.CancelledError) as e:
                    if kwargs.get("tunnel"):
                        kwargs["tunnel"].close()
                        await kwargs["tunnel"].wait_closed()

                    if client_instance and client_instance.server_key:
                        k = client_instance.server_key
                        accepted = await call_ui_async(ui_callbacks["ask_host_key"], conn.hostname, k.get_fingerprint(), k.get_algorithm())
                        if accepted:
                            db = Database(); db.open()
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
                finally:
                    _p = kwargs.get("password")
                    if isinstance(_p, bytearray):
                        for i in range(len(_p)): _p[i] = 0

        except asyncio.CancelledError:
            if "on_cancelled" in ui_callbacks: call_ui_sync(ui_callbacks["on_cancelled"])
            return None
        except Exception as e:
            err_msg = f"Authentication failed: {e}" if isinstance(e, asyncssh.PermissionDenied) else f"Connection failed: {e}"
            call_ui_sync(ui_callbacks["on_error"], err_msg)
            return None

    async def connect_and_start_session(
        self,
        conn: Connection,
        ui_callbacks: dict[str, Callable],
        output_cb: Callable[[bytes], None],
        exit_cb: Callable[[int], None],
        status_cb: Callable[[str], None] | None = None,
    ) -> Any:
        """Establish session and start PTY process."""
        res = await self._establish_connection(conn, ui_callbacks, status_cb)
        if not res: return
        
        connection, auth_info, _ = res
        
        session = await connection.create_process(
            term_type="xterm-256color",
            request_pty="force",
            encoding=None,
        )
        
        bridge = SessionBridge(session, output_cb, exit_cb)
        bridge._conn_ref = connection 
        call_ui_sync(ui_callbacks["on_connected"], bridge)
        
        async def background_tasks():
            if conn.auth_method == AuthMethod.VAULT:
                try:
                    from services.vault_service import VaultService
                    vs = VaultService.get()
                    if hasattr(vs.active_backend, 'sync'):
                        await vs.active_backend.sync()
                except Exception: pass
            await self._detect_os_if_needed(connection, conn, ui_callbacks)

        asyncio.create_task(background_tasks())
        await bridge.run()

    async def start_sftp_session(
        self,
        conn: Connection,
        ui_callbacks: dict[str, Callable],
        status_cb: Callable[[str], None] | None = None,
    ) -> tuple[asyncssh.SFTPClient, asyncssh.SSHClientConnection, dict[str, Any]] | None:
        """Establish connection and return an SFTPClient."""
        res = await self._establish_connection(conn, ui_callbacks, status_cb)
        if not res: return None
        
        connection, auth_info, _ = res
        
        try:
            if status_cb: call_ui_sync(status_cb, "Connected! Opening SFTP...")
            sftp = await connection.start_sftp_client()
            
            async def _detect_later():
                await asyncio.sleep(0.5)
                await self._detect_os_if_needed(connection, conn, ui_callbacks)
            asyncio.create_task(_detect_later())
            
            return sftp, connection, auth_info
        except Exception as e:
            call_ui_sync(ui_callbacks["on_error"], f"Failed to start SFTP: {e}")
            connection.close()
            return None

    async def _detect_os_if_needed(
        self, connection: asyncssh.SSHClientConnection, conn: Connection, ui_callbacks: dict[str, Callable]
    ) -> None:
        """Internal helper to identify remote OS and notify UI."""
        if not conn.os_id:
            try:
                res = await connection.run("cat /etc/os-release", check=False)
                if res.exit_status == 0 and res.stdout:
                    stdout = res.stdout
                    if isinstance(stdout, bytes): stdout = stdout.decode('utf-8', errors='ignore')
                    import re
                    match = re.search(r'^ID=[\'\"]?([a-zA-Z0-9_\-]+)[\'\"]?', stdout, re.MULTILINE)
                    if match:
                        os_id = match.group(1).lower()
                        conn.os_id = os_id
                        db = Database(); db.open()
                        try:
                            db.save_connection(conn)
                            if "on_os_detected" in ui_callbacks:
                                call_ui_sync(ui_callbacks["on_os_detected"], conn.id, os_id)
                        finally: db.close()
            except Exception: pass

    # --- Session Management ---
    def register_session(self, conn_id: str) -> SessionInfo:
        self._sessions[conn_id] = SessionInfo(conn_id, SessionState.CONNECTING, started_at=time.time())
        return self._sessions[conn_id]

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

    # ── Port Forwarding Methods ───────────────────────────────

    def _register_ssh_connection(self, connection_id: str, ssh_conn: asyncssh.SSHClientConnection) -> None:
        """Register an active SSH connection and auto-start its enabled port forwarding rules."""
        if connection_id not in self._active_ssh_connections:
            self._active_ssh_connections[connection_id] = []
        self._active_ssh_connections[connection_id].append(ssh_conn)

        # Watch for connection closure to trigger cleanup
        async def watch_conn() -> None:
            try:
                await ssh_conn.wait_closed()
            finally:
                await self._handle_connection_closed(connection_id, ssh_conn)
                call_ui_sync(self._notify_forward_rules_changed)

        asyncio.create_task(watch_conn())

        # Auto-start rules associated with this connection
        async def start_rules() -> None:
            db = Database()
            db.open()
            try:
                rules = db.list_forward_rules(connection_id)
                for rule in rules:
                    if rule.enabled:
                        try:
                            await self.start_forward_rule(rule)
                        except Exception:
                            pass
            finally:
                db.close()
            call_ui_sync(self._notify_forward_rules_changed)

        asyncio.create_task(start_rules())

    async def _handle_connection_closed(self, connection_id: str, ssh_conn: asyncssh.SSHClientConnection) -> None:
        """Clean up active listeners and connections mapping when a connection closes."""
        if connection_id in self._active_ssh_connections:
            if ssh_conn in self._active_ssh_connections[connection_id]:
                self._active_ssh_connections[connection_id].remove(ssh_conn)
            if not self._active_ssh_connections[connection_id]:
                del self._active_ssh_connections[connection_id]

        # Find and remove listeners associated with this closed connection
        closed_rule_ids = []
        for rule_id, (listener, conn) in list(self._active_listeners.items()):
            if conn == ssh_conn:
                self._active_listeners.pop(rule_id, None)
                closed_rule_ids.append(rule_id)

        # If there are other active connections for this connection_id, attempt to re-start the rules
        if closed_rule_ids:
            db = Database()
            db.open()
            try:
                for rule_id in closed_rule_ids:
                    rule_data = db.get_forward_rule(rule_id)
                    if rule_data and rule_data.enabled:
                        asyncio.create_task(self.start_forward_rule(rule_data))
            finally:
                db.close()

    async def start_forward_rule(self, rule: ForwardRule) -> None:
        """Start a port forwarding rule on the first active connection for its host."""
        if rule.id in self._active_listeners:
            return  # Already active

        conns = self._active_ssh_connections.get(rule.connection_id, [])
        if not conns:
            return  # No active connection to start it on

        ssh_conn = conns[0]
        bind_addr = rule.bind_address or "127.0.0.1"

        try:
            listener = None
            if rule.type == ForwardType.LOCAL:
                if not rule.remote_host or rule.remote_port is None:
                    raise ValueError("Remote host and port are required for Local forwarding")
                listener = await ssh_conn.forward_local_port(
                    bind_addr,
                    rule.bind_port,
                    rule.remote_host,
                    rule.remote_port
                )
            elif rule.type == ForwardType.REMOTE:
                if not rule.remote_host or rule.remote_port is None:
                    raise ValueError("Remote host and port are required for Remote forwarding")
                listener = await ssh_conn.forward_remote_port(
                    bind_addr,
                    rule.bind_port,
                    rule.remote_host,
                    rule.remote_port
                )
            elif rule.type == ForwardType.DYNAMIC:
                listener = await ssh_conn.forward_socks(
                    bind_addr,
                    rule.bind_port
                )

            if listener:
                self._active_listeners[rule.id] = (listener, ssh_conn)
                self._rule_errors.pop(rule.id, None)
                logger.info(f"Port forwarding rule {rule.id} started successfully")
        except Exception as e:
            self._rule_errors[rule.id] = str(e)
            logger.error(f"Failed to start port forwarding rule {rule.id}: {e}")
            raise e

    async def stop_forward_rule(self, rule_id: str) -> None:
        """Stop a running port forwarding listener."""
        self._rule_errors.pop(rule_id, None)
        if rule_id in self._active_listeners:
            listener, _ = self._active_listeners.pop(rule_id)
            try:
                listener.close()
                await listener.wait_closed()
                logger.info(f"Port forwarding rule {rule_id} stopped successfully")
            except Exception as e:
                logger.error(f"Error closing listener for rule {rule_id}: {e}")

    def get_forward_rule_status(self, rule: ForwardRule) -> str:
        """Return the status string of a forward rule."""
        if not rule.enabled:
            return "Stopped"
        if rule.id in self._active_listeners:
            return "Running"
        if rule.id in self._rule_errors:
            return "Error"
        if rule.connection_id in self._active_ssh_connections and self._active_ssh_connections[rule.connection_id]:
            # Connection is active but listener is not running and no explicit error is cached yet
            return "Error"
        return "Disconnected"

    def get_forward_rule_error(self, rule_id: str) -> str | None:
        """Return the error string for a rule if it exists."""
        return self._rule_errors.get(rule_id)

    def register_forward_rules_listener(self, callback: Callable[[], None]) -> None:
        """Register a callback to be notified when forward rules status changes."""
        self._forward_rules_listeners.append(callback)

    def unregister_forward_rules_listener(self, callback: Callable[[], None]) -> None:
        """Unregister a rules listener callback."""
        if callback in self._forward_rules_listeners:
            self._forward_rules_listeners.remove(callback)

    def _notify_forward_rules_changed(self) -> None:
        """Notify all registered listeners of a change."""
        for cb in self._forward_rules_listeners:
            try:
                cb()
            except Exception as e:
                logger.error(f"Error calling forward rules listener: {e}")
