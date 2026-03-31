# SPDX-License-Identifier: GPL-3.0-or-later

"""SFTP Backend Service — Pure asyncssh file operations with clean concurrency."""

from __future__ import annotations

import asyncio
import logging
import os
import stat
from typing import Any, Callable, Sequence

import asyncssh

from models.connection import Connection
from services.ssh_service import SSHService

logger = logging.getLogger(__name__)

# Type for file entries returned by list_dir
FileEntry = dict[str, Any]  # name, size, mtime, is_dir, permissions, uid, gid

# Progress callback: (bytes_done, total_bytes, filename)
ProgressCallback = Callable[[int, int, str], None]


def _progress_adapter(cb: ProgressCallback) -> Callable:
    """Adapt ProgressCallback to asyncssh's (src, dst, cur, total) signature."""
    def _handler(src: str, _dst: str, cur: int, total: int) -> None:
        cb(cur, total, os.path.basename(src))
    return _handler


class SftpService:
    """SFTP file operations over an established asyncssh SSH connection.

    Concurrency model
    -----------------
    _ctrl_lock : asyncio.Lock
        Serialises metadata operations (readdir, mkdir, rename, delete).
        Prevents navigation races when the user clicks around quickly.
    _xfer_sem  : asyncio.Semaphore(MAX_TRANSFERS)
        Allows up to MAX_TRANSFERS simultaneous file get/put operations.
        Metadata ops do NOT hold this semaphore.
    """

    MAX_TRANSFERS = 4

    def __init__(self, conn: Connection, ssh_service: SSHService) -> None:
        self._conn = conn
        self._ssh_service = ssh_service
        self._sftp: asyncssh.SFTPClient | None = None
        self._ssh_conn: asyncssh.SSHClientConnection | None = None
        self._auth_info: dict[str, Any] = {}

        self._ctrl_lock = asyncio.Lock()
        self._xfer_sem = asyncio.Semaphore(self.MAX_TRANSFERS)

    # ── Connection lifecycle ──────────────────────────────────────

    async def connect(
        self,
        ui_callbacks: dict[str, Callable],
        status_cb: Callable[[str], None] | None = None,
    ) -> bool:
        """Open the SFTP session. Returns True on success."""
        result = await self._ssh_service.start_sftp_session(
            self._conn, ui_callbacks, status_cb
        )
        if result is None:
            return False
        self._sftp, self._ssh_conn, self._auth_info = result
        logger.info("SftpService[%s]: Connected", self._conn.hostname)
        return True

    async def disconnect(self) -> None:
        """Close the SFTP client and the underlying SSH connection."""
        if self._sftp:
            try:
                self._sftp.exit()
            except Exception:
                pass
            self._sftp = None
        if self._ssh_conn:
            try:
                self._ssh_conn.close()
                await self._ssh_conn.wait_closed()
            except Exception:
                pass
            self._ssh_conn = None
        logger.info("SftpService[%s]: Disconnected", self._conn.hostname)

    @property
    def auth_info(self) -> dict[str, Any]:
        """Authentication details forwarded to RcloneService for FUSE mounts."""
        return self._auth_info

    # ── Directory listing ─────────────────────────────────────────

    async def list_dir(self, path: str) -> tuple[list[FileEntry], str]:
        """List *path* on the remote.

        Returns (entries, resolved_absolute_path).  Resolves the real path and
        reads the directory in a single lock acquisition to avoid race
        conditions with concurrent navigation.
        """
        async with self._ctrl_lock:
            resolved = await self._sftp.realpath(path)
            raw = await self._sftp.readdir(resolved)

        entries: list[FileEntry] = []
        for item in raw:
            if item.filename in (".", ".."):
                continue
            perms = item.attrs.permissions or 0
            entries.append({
                "name":        item.filename,
                "size":        item.attrs.size or 0,
                "mtime":       int(item.attrs.mtime or 0),
                "is_dir":      stat.S_ISDIR(perms),
                "permissions": perms,
                "uid":         item.attrs.uid or 0,
                "gid":         item.attrs.gid or 0,
            })

        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return entries, resolved

    async def get_cwd(self) -> str:
        """Return the connection's initial working directory."""
        return await self._sftp.getcwd()

    # ── Metadata mutations ──────────────────────────────────────────

    async def mkdir(self, path: str) -> None:
        """Create a remote directory."""
        async with self._ctrl_lock:
            await self._sftp.mkdir(path)

    async def create_file(self, path: str) -> None:
        """Create an empty remote file."""
        async with self._ctrl_lock:
            async with self._sftp.open(path, "w"):
                pass

    async def rename(self, old_path: str, new_path: str) -> None:
        """Rename / move a remote path."""
        async with self._ctrl_lock:
            await self._sftp.rename(old_path, new_path)

    async def remove(self, path: str, is_dir: bool) -> None:
        """Delete a remote file or directory (non-recursive for directories)."""
        async with self._ctrl_lock:
            if is_dir:
                await self._sftp.rmdir(path)
            else:
                await self._sftp.remove(path)

    # ── Bulk transfers ───────────────────────────────────────────────

    async def download(
        self,
        remote_path: str,
        local_path: str,
        progress_cb: ProgressCallback | None = None,
    ) -> None:
        """Download *remote_path* (file or directory) to *local_path*.

        Directories are transferred recursively via asyncssh.scp.
        Single files use sftp.get with optional per-chunk progress reporting.
        """
        async with self._xfer_sem:
            is_dir = await self._stat_is_dir(remote_path)
            if is_dir:
                await asyncssh.scp(
                    (self._ssh_conn, remote_path),
                    local_path,
                    preserve=True,
                    recurse=True,
                )
            else:
                await self._sftp.get(
                    remote_path,
                    local_path,
                    progress_handler=_progress_adapter(progress_cb) if progress_cb else None,
                )

    async def upload(
        self,
        local_paths: Sequence[str],
        remote_dir: str,
        progress_cb: ProgressCallback | None = None,
    ) -> None:
        """Upload one or more local files / directories into *remote_dir*."""
        async with self._xfer_sem:
            for lp in local_paths:
                if os.path.isdir(lp):
                    await asyncssh.scp(
                        lp,
                        (self._ssh_conn, remote_dir),
                        preserve=True,
                        recurse=True,
                    )
                else:
                    dest = remote_dir.rstrip("/") + "/" + os.path.basename(lp)
                    await self._sftp.put(
                        lp,
                        dest,
                        progress_handler=_progress_adapter(progress_cb) if progress_cb else None,
                    )

    # ── Single-file transfers (edit workflow) ────────────────────────

    async def get_file(self, remote_path: str, local_path: str) -> None:
        """Download a single file.  Used by the edit workflow."""
        async with self._xfer_sem:
            await self._sftp.get(remote_path, local_path)

    async def put_file(self, local_path: str, remote_path: str) -> None:
        """Upload a single file.  Used to sync edits back to remote."""
        async with self._xfer_sem:
            await self._sftp.put(local_path, remote_path)

    # ── Internal helpers ─────────────────────────────────────────────

    async def _stat_is_dir(self, path: str) -> bool:
        """Stat *path* without holding _ctrl_lock (used during transfers)."""
        try:
            attrs = await self._sftp.stat(path)
            return stat.S_ISDIR(attrs.permissions or 0)
        except Exception:
            return False
