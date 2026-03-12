# SPDX-License-Identifier: GPL-3.0-or-later

"""AsyncSSH engine running in a dedicated background thread."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Callable

from gi.repository import GLib

logger = logging.getLogger(__name__)


def call_ui_sync(func: Callable[..., Any], *args: Any) -> None:
    """Run a callable in GTK main thread without waiting for a result."""
    def _once() -> bool:
        func(*args)
        return GLib.SOURCE_REMOVE  # Explicit False — run only once
    GLib.idle_add(_once)

def call_ui_async(func: Callable[..., Any], *args: Any) -> asyncio.Future:
    """Run a callable in GTK main thread that requires user interaction.
    
    The func must accept a `resolve` callback as its LAST argument.
    It calls `resolve(result)` when the dialog or interaction completes.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def resolve(result: Any) -> None:
        if not future.done():
            loop.call_soon_threadsafe(future.set_result, result)

    def _ui_callback() -> bool:
        try:
            func(*args, resolve)
        except Exception as e:
            if not future.done():
                loop.call_soon_threadsafe(future.set_exception, e)
        return False  # Run only once

    GLib.idle_add(_ui_callback)
    return future


class AsyncEngine:
    """Manages the background asyncio event loop for asyncssh operations."""
    
    _instance: AsyncEngine | None = None
    
    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._loop_ready = threading.Event()

    @classmethod
    def get(cls) -> AsyncEngine:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
        
    def start(self) -> None:
        """Start the background asyncio thread."""
        if self._thread is not None and self._thread.is_alive():
            return

        self._thread = threading.Thread(
            target=self._run_loop,
            name="SentinelAsyncEngine",
            daemon=True,
        )
        self._thread.start()
        self._loop_ready.wait()  # Wait for loop to be created
        
    def _run_loop(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._loop_ready.set()
        
        logger.info("AsyncSSH event loop started")
        try:
            self.loop.run_forever()
        finally:
            # Clean up pending tasks
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()
            logger.info("AsyncSSH event loop stopped")

    def run_coroutine(self, coro: Any) -> Any:
        """Submit a coroutine to run in the background loop.
        
        Returns a concurrent.futures.Future that can be cancelled.
        """
        if self.loop is None or not self.loop.is_running():
            raise RuntimeError("Async engine is not running")
            
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self) -> None:
        """Stop the event loop and background thread."""
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self._thread:
                self._thread.join(timeout=2.0)
