# SPDX-License-Identifier: GPL-3.0-or-later

"""AsyncSSH client integration for GTK/VTE."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

import asyncssh

from models.connection import AuthMethod, Connection
from services.async_engine import call_ui_async, call_ui_sync, AsyncEngine

logger = logging.getLogger(__name__)


class SentinelSSHClient(asyncssh.SSHClient):
    """Custom SSH Client that bridges authentication prompts to GTK UI."""

    def __init__(
        self,
        connection: Connection,
        ui_callbacks: dict[str, Callable],
        password_provider: Callable[[], str | None] | None = None,
    ) -> None:
        super().__init__()
        self._conn = connection
        self._ui_callbacks = ui_callbacks
        self._password_provider = password_provider

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        """Validate the remote host key.

        asyncssh calls validate_host_public_key() (with addr) when a presented
        key is not found in the known_hosts list. The actual DB lookup + UI
        prompt is performed by the BoundClient subclass in
        SSHService.connect_and_start_session. This base implementation returns
        False as a safe default so that any code path that forgets to subclass
        this method will not silently trust all host keys.
        """
        return False

    async def _handle_auth(
        self,
        prompt_type: str,
        prompt_text: str,
        allow_empty: bool = False,
    ) -> str:
        """Helper to request input from the UI."""
        future = self._ui_callbacks.get(prompt_type)
        if not future:
            logger.error(f"No UI callback registered for {prompt_type}")
            return ""
            
        return await call_ui_async(future, prompt_text, self._conn)

    # ── Authentication Callbacks ──────────────────────────────

    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
        logger.info(f"Connection made to {self._conn.hostname}")

    def kbdint_auth_requested(self) -> str:
        """Always allow keyboard-interactive auth to proceed.
        
        asyncssh's default implementation can return None if the password was already
        consumed. We override this to return an empty string so the server can
        pick the submethod, allowing our kbdint_challenge_received to use the
        cached password or prompt the user.
        """
        return ""

    async def kbdint_challenge_received(
        self, name: str, instruction: str, lang: str, prompts: list[tuple[str, bool]]
    ) -> list[str]:
        """Handle keyboard-interactive authentication challenges."""
        # Many servers (like Alpine/Dropbear) use keyboard-interactive instead of password auth.
        # We'll just ask for the password if this happens.
        cb = self._ui_callbacks.get("ask_password")
        if not cb or not prompts:
            return []
            
        results = []
        for prompt, echo in prompts:
            # Try pre-provided password first (e.g. from Vault or previous entry)
            if self._password_provider:
                import inspect
                if inspect.iscoroutinefunction(self._password_provider):
                    pwd = await self._password_provider()
                else:
                    pwd = self._password_provider()
                
                if pwd is not None:
                    results.append(pwd)
                    continue

            # Usually it's just one prompt for "Password: "
            # Use the server's prompt text if possible
            res = await call_ui_async(cb, self._conn)
            if res is None:
                raise asyncio.CancelledError("User cancelled password input")
                
            with res:
                results.append(res.get_str())
                
        return results

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info(f"Connection lost to {self._conn.hostname}: {exc}")
        if cb := self._ui_callbacks.get("on_disconnected"):
            call_ui_sync(cb, exc)

    def auth_completed(self) -> None:
        logger.info(f"Authentication successful for {self._conn.hostname}")



class SessionBridge:
    """Bridges SSH process I/O with VTE Terminal."""
    
    def __init__(
        self,
        process: asyncssh.SSHClientProcess,
        output_cb: Callable[[bytes], None],
        exit_cb: Callable[[int], None],
    ) -> None:
        self.process = process
        self._output_cb = output_cb
        self._exit_cb = exit_cb
        self._read_task: asyncio.Task | None = None
        
    async def run(self) -> None:
        """Start reading stdout until process exits."""
        self._read_task = asyncio.create_task(self._pump_output())
        
        try:
            await self.process.wait_closed()
        except Exception as e:
            logger.error(f"Error waiting for SSH process: {e}")
            
        if self._read_task:
            self._read_task.cancel()
            
        exit_status = self.process.returncode
        call_ui_sync(self._exit_cb, exit_status if exit_status is not None else -1)

    async def _pump_output(self) -> None:
        """Pump output from asyncssh to VTE feed."""
        try:
            while not self.process.stdout.at_eof():
                # Read chunks of raw bytes
                data = await self.process.stdout.read(4096)
                if not data:
                    break
                # Pass un-decoded bytes to VTE terminal
                call_ui_sync(self._output_cb, data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error reading SSH stdout: {e}")

    def write(self, data: bytes) -> None:
        """Write user input from VTE to SSH channel. Safe to call from any thread."""
        def _do_write():
            try:
                self.process.stdin.write(data)
            except Exception as e:
                logger.error(f"Error writing to SSH stdin: {e}")
        
        engine = AsyncEngine.get()
        if engine.loop:
            engine.loop.call_soon_threadsafe(_do_write)

    def resize(self, columns: int, rows: int) -> None:
        """Resize the remote PTY. Safe to call from any thread."""
        def _do_resize():
            try:
                self.process.change_terminal_size(columns, rows)
            except Exception as e:
                logger.error(f"Error resizing PTY: {e}")
                
        engine = AsyncEngine.get()
        if engine.loop:
            engine.loop.call_soon_threadsafe(_do_resize)

    def close(self) -> None:
        """Close the remote SSH connection explicitly."""
        def _do_close():
            try:
                # self._conn_ref is injected from SSHService.connect_and_start_session
                if hasattr(self, "_conn_ref") and self._conn_ref:
                    self._conn_ref.close()
                else:
                    self.process.close()
            except Exception as e:
                logger.error(f"Error closing SSH session: {e}")

        engine = AsyncEngine.get()
        if engine.loop:
            engine.loop.call_soon_threadsafe(_do_close)
