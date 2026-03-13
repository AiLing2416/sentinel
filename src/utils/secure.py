# SPDX-License-Identifier: GPL-3.0-or-later

"""Secure memory management to prevent sensitive data swapping or lingering."""

import ctypes
import logging

logger = logging.getLogger(__name__)

class SecureBytes:
    """Secure byte string wrapper: zeroes memory upon destruction to prevent page leaking.
    Attempts to use mlock() to lock memory pages to prevent them from being swapped to disk.
    """

    def __init__(self, data: bytes | bytearray | str):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._buf = bytearray(data)
        self._lock_memory()

    def _lock_memory(self) -> None:
        """Lock memory pages to prevent swapping to disk."""
        try:
            # Load libc on Linux/Unix
            libc = ctypes.CDLL("libc.so.6")
            # Get pointer to bytearray buffer
            char_array = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
            ptr = ctypes.cast(char_array, ctypes.c_void_p)
            # mlock(const void *addr, size_t len)
            res = libc.mlock(ptr, ctypes.c_size_t(len(self._buf)))
            if res != 0:
                logger.debug("mlock() failed to lock secure memory buffer.")
        except Exception as e:
            logger.debug(f"Memory locking (mlock) unavailable or failed: {e}")

    def unsafe_get_bytes(self) -> bytes:
        """Get the protected data as bytes.
        WARNING: This creates a copy in Python memory which cannot be wiped.
        Use get_view() instead whenever possible.
        """
        return bytes(self._buf)

    def unsafe_get_str(self) -> str:
        """Get the protected data as string.
        WARNING: This creates a copy in Python memory which cannot be wiped.
        Use get_view() instead whenever possible.
        """
        return self._buf.decode("utf-8")

    def get_view(self) -> memoryview:
        """Get a memoryview of the protected buffer.
        When clear() is called, the content of this view will also be zeroed.
        This is the preferred way to access data for subprocesses or asyncssh.
        """
        return memoryview(self._buf)

    def __bytes__(self) -> bytes:
        """Prevent accidental conversion to bytes."""
        raise TypeError(
            "Implicit conversion of SecureBytes to bytes is disabled for security. "
            "Use get_view() or unsafe_get_bytes() if absolutely necessary."
        )

    def __str__(self) -> str:
        return "********"

    def __repr__(self) -> str:
        return f"<SecureBytes len={len(self._buf)} at {hex(id(self))}>"

    def __len__(self) -> int:
        return len(self._buf)

    def clear(self) -> None:
        """Zero out the memory buffer."""
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def __del__(self) -> None:
        self.clear()

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()
