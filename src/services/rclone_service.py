# SPDX-License-Identifier: GPL-3.0-or-later

"""Rclone FUSE mount and single-file transfer service for Sentinel."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from gi.repository import GLib

from models.connection import Connection
from utils.secure import SecureBytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rclone binary location
# ---------------------------------------------------------------------------

def _find_rclone() -> str:
    candidates = [
        "/app/bin/rclone",
        str(Path(__file__).parent.parent.parent / "bin" / "rclone"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("rclone") or "rclone"

RCLONE_BIN = _find_rclone()

# Edit temp files must live somewhere BOTH the Flatpak sandbox and the host
# can see.  /tmp is a private mount namespace inside bwrap — the host's
# xdg-open cannot access files written there.
# GLib.get_user_cache_dir() returns the app's XDG_CACHE_HOME, which is:
#   ~/.var/app/io.github.ailing2416.sentinel/cache/  (inside sandbox)
# … and that same path is visible to host processes such as xdg-open.
def _get_edit_root() -> str:
    return os.path.join(GLib.get_user_cache_dir(), "sentinel", "edit")



# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

@dataclass
class _MountState:
    """Tracks a single live rclone mount process."""
    proc:       asyncio.subprocess.Process
    tmpdir:     str   # Owns rclone.conf + any temp key files; deleted on unmount
    mount_path: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class RcloneService:
    """Singleton façade for rclone FUSE mounting and file copy operations.

    Mount lifecycle
    ---------------
    • ``mount()``  — starts ``rclone mount`` as a subprocess with read-write
      VFS cache, waits for the mountpoint to appear, then returns the path.
    • ``unmount()`` — terminates the process, deletes the temp config dir, and
      forces a kernel unmount if the process left the mountpoint stale.
    • ``unmount_all()`` — called at application shutdown.

    Edit workflow
    -------------
    ``download_for_edit()`` uses ``rclone copyto`` to fetch a single remote
    file into ``/tmp/sentinel/edit/{conn_id}/{hash}/{filename}``.
    The caller opens the file with the default or chosen application, monitors
    it for changes, and calls ``upload_file()`` to push changes back.
    ``upload_file()`` uses ``rclone copyto`` in the reverse direction.

    Cross-host transfer
    -------------------
    ``transfer()`` builds a two-section rclone config and runs ``rclone copy``
    between any two SFTP connections.
    """

    _instance: RcloneService | None = None

    @classmethod
    def get(cls) -> RcloneService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._mounts: dict[str, _MountState] = {}

    # ── Mount path ────────────────────────────────────────────────

    def get_mount_path(self, connection_id: str) -> str:
        """Return the local directory used as the FUSE mountpoint."""
        cache = GLib.get_user_cache_dir()
        return os.path.join(cache, "sentinel", "mounts", connection_id)

    def is_mounted(self, connection_id: str) -> bool:
        return connection_id in self._mounts

    # ── Mount ─────────────────────────────────────────────────────

    async def mount(
        self,
        conn: Connection,
        auth_info: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        """Ensure an rclone FUSE mount is active for *conn*.

        Returns ``(mount_path, None)`` on success or ``(None, error_message)``
        on failure.  Idempotent: returns the cached path if already mounted.
        """
        if conn.id in self._mounts:
            return self._mounts[conn.id].mount_path, None

        mount_path = self.get_mount_path(conn.id)
        os.makedirs(mount_path, exist_ok=True)
        await _force_unmount(mount_path)   # clear any stale mount

        tmpdir = tempfile.mkdtemp(prefix="sentinel_rclone_")
        try:
            conf = await self._write_config(conn, auth_info, tmpdir)
            cmd = [
                RCLONE_BIN, "mount", "remote:/", mount_path,
                "--config", conf,
                "--vfs-cache-mode", "full",
                "--vfs-cache-max-age", "30s",
                "--dir-cache-time",   "5s",
                "--transfers",        "4",
                "--log-level",        "INFO",
                # Explicitly NOT --read-only so edits are writable
            ]
            logger.info("RcloneService: mounting %s -> %s", conn.hostname, mount_path)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )

            ok, err = await _wait_for_mount(proc, mount_path)
            if not ok:
                if proc.returncode is None:
                    proc.terminate()
                shutil.rmtree(tmpdir, ignore_errors=True)
                return None, err or "Mount failed"

            state = _MountState(proc=proc, tmpdir=tmpdir, mount_path=mount_path)
            self._mounts[conn.id] = state
            asyncio.create_task(self._monitor(conn.id, state))
            logger.info("RcloneService: mount active at %s", mount_path)
            return mount_path, None

        except Exception as exc:
            shutil.rmtree(tmpdir, ignore_errors=True)
            logger.exception("RcloneService: mount exception")
            return None, str(exc)

    async def unmount(self, connection_id: str) -> None:
        """Unmount and clean up resources for *connection_id*."""
        state = self._mounts.pop(connection_id, None)
        if state is None:
            return
        state.proc.terminate()
        try:
            await asyncio.wait_for(state.proc.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            state.proc.kill()
        shutil.rmtree(state.tmpdir, ignore_errors=True)
        await _force_unmount(state.mount_path)
        logger.info("RcloneService: unmounted %s", connection_id)

    def unmount_all(self) -> None:
        """Terminate all active mounts synchronously (app shutdown)."""
        for state in list(self._mounts.values()):
            state.proc.terminate()
        self._mounts.clear()

    async def _monitor(self, conn_id: str, state: _MountState) -> None:
        """Background task: clean up when the rclone process exits on its own."""
        await state.proc.wait()
        removed = self._mounts.pop(conn_id, None)
        if removed:
            shutil.rmtree(removed.tmpdir, ignore_errors=True)
            await _force_unmount(removed.mount_path)
        logger.info("RcloneService: mount for %s exited", conn_id)

    # ── Download for edit ──────────────────────────────────────────

    async def download_for_edit(
        self,
        conn: Connection,
        auth_info: dict[str, Any],
        remote_path: str,
    ) -> tuple[str | None, str | None]:
        """Copy a single remote file to a local temp path for external editing.

        Uses ``rclone copyto`` so no FUSE mount is needed.
        Returns ``(local_file_path, None)`` on success or ``(None, error)``.
        The local file lives under ``/tmp/sentinel/edit/{conn_id}/{hash}/``.
        """
        filename  = os.path.basename(remote_path)
        dest_dir  = os.path.join(_get_edit_root(), conn.id, f"{abs(hash(remote_path)):x}")
        local_path = os.path.join(dest_dir, filename)
        os.makedirs(dest_dir, exist_ok=True)

        tmpdir = tempfile.mkdtemp(prefix="sentinel_rclone_edit_")
        try:
            conf = await self._write_config(conn, auth_info, tmpdir)
            cmd = [
                RCLONE_BIN, "copyto",
                f"remote:{remote_path}",
                local_path,
                "--config", conf,
                "--log-level", "ERROR",
            ]
            logger.info("RcloneService: download_for_edit %s -> %s", remote_path, local_path)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                err = stderr.decode().strip()
                logger.error("RcloneService: copyto failed: %s", err)
                return None, err or "Download failed"
            return local_path, None

        except Exception as exc:
            logger.exception("RcloneService: download_for_edit exception")
            return None, str(exc)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Upload (sync back after editing) ──────────────────────────

    async def upload_file(
        self,
        conn: Connection,
        auth_info: dict[str, Any],
        local_path: str,
        remote_path: str,
    ) -> tuple[bool, str | None]:
        """Push a local file back to the remote path using ``rclone copyto``."""
        tmpdir = tempfile.mkdtemp(prefix="sentinel_rclone_up_")
        try:
            conf = await self._write_config(conn, auth_info, tmpdir)
            cmd = [
                RCLONE_BIN, "copyto",
                local_path,
                f"remote:{remote_path}",
                "--config", conf,
                "--log-level", "ERROR",
            ]
            logger.info("RcloneService: upload_file %s -> %s", local_path, remote_path)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                err = stderr.decode().strip()
                logger.error("RcloneService: upload failed: %s", err)
                return False, err or "Upload failed"
            return True, None

        except Exception as exc:
            logger.exception("RcloneService: upload_file exception")
            return False, str(exc)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Cross-host transfer ────────────────────────────────────────

    async def transfer(
        self,
        src_conn: Connection,
        src_auth: dict[str, Any],
        src_path: str,
        dst_conn: Connection,
        dst_auth: dict[str, Any],
        dst_path: str,
        progress_cb: Callable[[float, str], None] | None = None,
    ) -> tuple[bool, str | None]:
        """Transfer files between two SFTP hosts via rclone.

        Builds a two-section config file so rclone can address both remotes
        simultaneously without touching the system-wide rclone config.
        """
        tmpdir = tempfile.mkdtemp(prefix="sentinel_rclone_xfer_")
        try:
            src_lines = await self._remote_section("src", src_conn, src_auth, tmpdir)
            dst_lines = await self._remote_section("dst", dst_conn, dst_auth, tmpdir)

            conf_path = os.path.join(tmpdir, "rclone.conf")
            with open(conf_path, "w") as f:
                f.write("\n".join(src_lines) + "\n\n")
                f.write("\n".join(dst_lines) + "\n")
            os.chmod(conf_path, 0o600)

            cmd = [
                RCLONE_BIN, "copyto",
                f"src:{src_path}",
                f"dst:{dst_path}",
                "--config", conf_path,
                "--log-level", "ERROR",
            ]
            logger.info(
                "RcloneService: transfer %s:%s -> %s:%s",
                src_conn.hostname, src_path, dst_conn.hostname, dst_path,
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                err = stderr.decode().strip()
                logger.error("RcloneService: transfer failed: %s", err)
                return False, err or "Transfer failed"
            return True, None

        except Exception as exc:
            logger.exception("RcloneService: transfer exception")
            return False, str(exc)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Config helpers ─────────────────────────────────────────────

    async def _write_config(
        self,
        conn: Connection,
        auth_info: dict[str, Any],
        tmpdir: str,
        remote_name: str = "remote",
    ) -> str:
        """Write a single-remote rclone config to *tmpdir* and return its path."""
        lines = await self._remote_section(remote_name, conn, auth_info, tmpdir)
        conf = os.path.join(tmpdir, "rclone.conf")
        with open(conf, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(conf, 0o600)
        return conf

    async def _remote_section(
        self,
        remote_name: str,
        conn: Connection,
        auth_info: dict[str, Any],
        tmpdir: str,
    ) -> list[str]:
        """Return rclone config lines for one [remote_name] SFTP section."""
        lines = [
            f"[{remote_name}]",
            "type = sftp",
            f"host = {conn.hostname}",
            f"port = {conn.port or 22}",
            f"user = {conn.username or 'root'}",
            "ask_password = false",
            "key_use_agent = false",
        ]

        if auth_info.get("password"):
            lines.append(f"pass = {await self._obscure(auth_info['password'])}")

        if auth_info.get("key_path"):
            lines.append(f"key_file = {auth_info['key_path']}")
        elif auth_info.get("private_key_pem"):
            key_path = os.path.join(tmpdir, f"id_{remote_name}")
            pem = auth_info["private_key_pem"]
            content = pem.unsafe_get_str() if isinstance(pem, SecureBytes) else str(pem)
            with open(key_path, "w") as f:
                f.write(content.strip() + "\n")
            os.chmod(key_path, 0o600)
            lines.append(f"key_file = {key_path}")

        if auth_info.get("key_passphrase"):
            lines.append(
                f"key_file_pass = {await self._obscure(auth_info['key_passphrase'])}"
            )

        return lines

    async def _obscure(self, secret: Any) -> str:
        """Run ``rclone obscure`` on *secret* and return the obscured string."""
        if isinstance(secret, SecureBytes):
            data = bytes(secret.get_view())
        elif isinstance(secret, str):
            data = secret.encode()
        else:
            data = bytes(secret)

        proc = await asyncio.create_subprocess_exec(
            RCLONE_BIN, "obscure", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=data)
        if proc.returncode != 0:
            raise RuntimeError(f"rclone obscure failed: {stderr.decode().strip()}")
        return stdout.decode().strip()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

async def _wait_for_mount(
    proc: asyncio.subprocess.Process,
    mount_path: str,
    timeout: float = 10.0,
) -> tuple[bool, str | None]:
    """Poll until the mountpoint appears or the process exits / times out.

    Also drains stderr in the background so the pipe buffer never fills and
    logs any error lines rclone emits.
    """
    error_lines: list[str] = []

    async def _drain() -> None:
        assert proc.stderr
        async for raw in proc.stderr:
            line = raw.decode().strip()
            if not line:
                continue
            logger.debug("rclone: %s", line)
            lower = line.lower()
            if any(k in lower for k in ("error", "failed", "fatal", "denied")):
                error_lines.append(line)

    drain_task = asyncio.create_task(_drain())
    deadline = asyncio.get_event_loop().time() + timeout
    try:
        while asyncio.get_event_loop().time() < deadline:
            if proc.returncode is not None:
                await asyncio.sleep(0.05)   # let drain finish one more iteration
                return False, (error_lines[-1] if error_lines else "rclone exited unexpectedly")
            if await _is_mounted(mount_path):
                return True, None
            await asyncio.sleep(0.1)
    finally:
        drain_task.cancel()
        try:
            await drain_task
        except asyncio.CancelledError:
            pass

    return False, f"Mount timed out after {timeout:.0f}s"


async def _is_mounted(path: str) -> bool:
    """Return True if *path* appears in ``/proc/mounts``."""
    def _check() -> bool:
        if os.path.exists("/proc/mounts"):
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 1 and parts[1] == path:
                        return True
            return False
        return os.path.ismount(path)

    try:
        return await asyncio.to_thread(_check)
    except Exception:
        return False


async def _force_unmount(mount_path: str) -> None:
    """Best-effort unmount of *mount_path*, trying fusermount3 then umount."""
    for cmd in (["fusermount3", "-zu", mount_path], ["umount", "-f", mount_path]):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return
        except Exception:
            continue
