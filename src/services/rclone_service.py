import asyncio
import logging
import os
import tempfile
from pathlib import Path

import re
import typing

from models.connection import Connection
from services.async_engine import AsyncEngine
from utils.secure import SecureBytes

logger = logging.getLogger(__name__)

# Constants
PROJECT_ROOT = Path(__file__).parent.parent.parent
RCLONE_BIN = str(PROJECT_ROOT / "bin" / "rclone")
SENTINEL_MOUNTS_DIR = os.path.expanduser("~/.cache/sentinel/mounts")

# Security: Expected SHA256 of the bundled binary
RCLONE_SHA256 = "66222d029e8135c0aedd239cc79c66ce5a7aa2063a97731ba7df4ec8e22e60cf"

class RcloneService:
    """Provides transparent FUSE mount using rclone for SFTP connections."""
    
    _instance = None
    
    @classmethod
    def get(cls) -> "RcloneService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._engine = AsyncEngine.get()
        self._active_mounts: dict[str, asyncio.subprocess.Process] = {}

    def is_mounted(self, connection_id: str) -> bool:
        """Sync check if a connection is currently mounted."""
        return connection_id in self._active_mounts

    async def ensure_rclone(self) -> bool:
        """Verify rclone bundled binary exists and is authentic."""
        if os.path.exists(RCLONE_BIN) and os.access(RCLONE_BIN, os.X_OK):
            if await self._verify_binary(RCLONE_BIN, RCLONE_SHA256):
                return True
            else:
                logger.error("Rclone binary integrity check FAILED! Security risk detected.")
                return False
            
        logger.error(f"Bundled rclone binary not found or not executable at {RCLONE_BIN}")
        return False

    async def _verify_binary(self, path: str, expected_sha: str) -> bool:
        """Verify the SHA256 hash of a file."""
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
        except Exception as e:
            logger.error(f"Binary verification failed for {path}: {e}")
            return False

    async def _obscure_password(self, password: SecureBytes | str) -> str:
        """Obscure password using rclone obscure via stdin."""
        pwd_view = password.get_view() if isinstance(password, SecureBytes) else password.encode()
        
        proc = await asyncio.create_subprocess_exec(
            RCLONE_BIN, "obscure", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate(input=pwd_view)
        if proc.returncode != 0:
            raise Exception(f"Rclone obscure failed: {stderr.decode()}")
        return stdout.decode().strip()

    def get_mount_path(self, connection_id: str) -> str:
        """Get expected local mount path."""
        return os.path.join(SENTINEL_MOUNTS_DIR, connection_id)

    async def _is_path_mounted_safe(self, mount_path: str) -> bool:
        """Check /proc/mounts to see if path is mounted without triggering FUSE calls."""
        try:
            def _check():
                if not os.path.exists("/proc/mounts"):
                    logger.debug(f"'/proc/mounts' not found, falling back to os.path.ismount for {mount_path}")
                    return os.path.ismount(mount_path)
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) > 1 and parts[1] == mount_path:
                            logger.debug(f"Path {mount_path} found in /proc/mounts.")
                            return True
                logger.debug(f"Path {mount_path} not found in /proc/mounts.")
                return False
            return await asyncio.to_thread(_check)
        except Exception as e:
            logger.warning(f"Error checking mount status for {mount_path}: {e}")
            return False

    async def _unmount_if_stale(self, mount_path: str):
        """Unmount in case it was left over using lazy unmount. Works on Linux & BSD."""
        try:
            logger.debug(f"Attempting to clear stale mount: {mount_path}")
            # Try fusermount3 first (Linux)
            proc = await asyncio.create_subprocess_exec(
                "fusermount3", "-zu", mount_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
                if proc.returncode == 0:
                    logger.debug(f"Successfully unmounted stale mount via fusermount3: {mount_path}")
                    return
            except: pass
            
            # Fallback to standard umount (BSD/Linux fallback)
            # -f for force, -l for lazy (non-POSIX, might work on some systems)
            # On FreeBSD: umount -f
            cmd = ["umount", "-f", mount_path]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except Exception as e:
            logger.debug(f"Stale unmount attempt for {mount_path} ignored: {e}")

    async def mount(self, conn: Connection, auth_info: dict) -> tuple[str | None, str | None]:
        """Mount SFTP FUSE using rclone. Returns (file_uri, error_msg)."""
        if not await self.ensure_rclone():
            return None, "Rclone binary missing or failed to download"
            
        mount_path = self.get_mount_path(conn.id)
        if conn.id in self._active_mounts:
            # Already mounted
            return f"file://{mount_path}", None
            
        os.makedirs(mount_path, exist_ok=True)
        await self._unmount_if_stale(mount_path)
        
        args = [
            RCLONE_BIN,
            "mount",
            ":sftp:/", mount_path,
            "--sftp-host", conn.hostname,
            "--vfs-cache-mode", "full",
            "--vfs-cache-max-age", "5s",
            "--dir-cache-time", "5s",
            "--read-only",               # Protect remote from accidental mount-side writes
            "--sftp-ask-password=false",
            "--sftp-key-use-agent=false",
            "--daemon-timeout", "10s",
        ]
        
        if conn.port:
            args.extend(["--sftp-port", str(conn.port)])
        if conn.username:
            args.extend(["--sftp-user", conn.username])
            
        # Securely pass keys or passwords via temporary config
        config_path = None
        try:
            config_path, _ = await self._write_temp_config(conn, auth_info, "mount_remote")
            args.extend(["--config", config_path])
            
            # Use the remote name defined in the config
            args[2] = "mount_remote:/"
            
            # Clean start: Ensure it's not mounted and path is clear
            await self._unmount_if_stale(mount_path)
            if not os.path.exists(mount_path):
                os.makedirs(mount_path, exist_ok=True)
            
            logger.info(f"Starting rclone mount for {conn.hostname} at {mount_path}")
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            
            err_output = []
            async def _read_stderr():
                while True:
                    line = await proc.stderr.readline()
                    if not line: break
                    msg = line.decode().strip()
                    if msg: 
                        logger.warning(f"Rclone [{conn.hostname}]: {msg}")
                        err_output.append(msg)
            asyncio.create_task(_read_stderr())
            
            success = False
            logger.info(f"Polling mount status for {mount_path}...")
            for i in range(50):
                if proc.returncode is not None:
                    logger.error(f"Rclone mount process exited early: {proc.returncode}")
                    break
                
                if await self._is_path_mounted_safe(mount_path):
                    logger.info(f"Mount point {mount_path} verified in /proc/mounts after {i*0.1:.1f}s")
                    # One final check: can we actually see the directory?
                    try:
                        def _test_dir():
                            return os.path.isdir(mount_path)
                        if await asyncio.wait_for(asyncio.to_thread(_test_dir), timeout=0.5):
                            success = True
                            break
                    except: pass
                
                await asyncio.sleep(0.1)
            
            if not success:
                err_summary = " ".join(err_output[-2:]) if err_output else "Mount point failed to become responsive"
                logger.error(f"Mount readiness check failed after 5s for {mount_path}. Last error: {err_summary}")
                if proc.returncode is None:
                    proc.terminate()
                return None, err_summary

            # Process is running and mount is ready
            self._active_mounts[conn.id] = dict(proc=proc, config_path=config_path)
            
            # Monitor loop
            async def _monitor_mount():
                await proc.wait()
                logger.info(f"Rclone mount for {conn.hostname} terminated (code {proc.returncode})")
                if config_path and os.path.exists(config_path):
                    try: os.remove(config_path)
                    except: pass
                self._active_mounts.pop(conn.id, None)
                await self._unmount_if_stale(mount_path)
            
            asyncio.create_task(_monitor_mount())
            return f"file://{mount_path}", None
                
        except Exception as e:
            logger.error(f"Failed to mount rclone: {e}")
            if config_path and os.path.exists(config_path):
                try: os.remove(config_path)
                except: pass
            return None, str(e)

    async def unmount(self, connection_id: str):
        """Unmount a specific connection."""
        data = self._active_mounts.get(connection_id)
        if data:
            proc = data["proc"]
            if proc.returncode is None:
                proc.terminate()
            # The monitor task will handle the rest
        else:
            mount_path = self.get_mount_path(connection_id)
            await self._unmount_if_stale(mount_path)

    async def transfer(self, 
                       src_conn: Connection, src_auth: dict, src_path: str,
                       dst_conn: Connection, dst_auth: dict, dst_path: str,
                       on_progress: typing.Callable[[float, str], None] | None = None) -> tuple[bool, str | None]:
        """Perform remote-to-remote transfer using rclone with performance tuning."""
        if not await self.ensure_rclone():
            return False, "Rclone missing"

        # 1. Create temporary rclone config
        config_path, temp_files = await self._generate_transfer_config(src_conn, src_auth, dst_conn, dst_auth)
        
        try:
            # 2. Build command
            # High-performance flags:
            # --transfers=4: Parallel file transfers
            # --buffer-size=32M: Memory buffer per file
            # --sftp-concurrency=16: SFTP concurrent requests
            # --stats=1s: Progress update interval
            args = [
                RCLONE_BIN, 
                "copy", 
                "--config", config_path,
                "src:" + src_path, 
                "dst:" + os.path.dirname(dst_path),
                "--transfers", "4",
                "--buffer-size", "32M",
                "--sftp-concurrency", "16",
                "--stats", "1s",
                "-P"
            ]
            
            # If src_path is a file, we want to ensure it's copied to dst_path specifically 
            # but rclone copy src:file dst_dir: copies it into the dir.
            # If dst_path is the final file name:
            if not dst_path.endswith("/"):
                # rclone copyto is better for specific renaming
                args[1] = "copyto"
                args[5] = "dst:" + dst_path

            logger.info(f"Starting rclone transfer: {src_conn.hostname} -> {dst_conn.hostname}")
            
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            # 3. Parse progress
            # Rclone -P output example:
            # Transferred:   	   1.234 MiB / 10.552 MiB, 12%, 1.234 MiB/s, ETA 7s
            progress_re = re.compile(r"Transferred:.* (\d+)%,")
            
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode(errors="replace").strip()
                if not line_str: continue
                
                # Check for progress
                match = progress_re.search(line_str)
                if match and on_progress:
                    percent = float(match.group(1))
                    on_progress(percent, line_str)
                elif "error" in line_str.lower():
                    logger.warning(f"Rclone transfer log: {line_str}")

            await proc.wait()
            
            if proc.returncode == 0:
                return True, None
            else:
                return False, f"Rclone exited with code {proc.returncode}"

        except Exception as e:
            logger.error(f"Transfer failed: {e}")
            return False, str(e)
        finally:
            # Cleanup temp files (keys and config)
            for f in temp_files:
                if f and os.path.exists(f):
                    try: os.remove(f)
                    except: pass
            if os.path.exists(config_path):
                try: os.remove(config_path)
                except: pass

    async def _write_temp_config(self, 
                               src_conn: Connection, src_auth: dict, 
                               dst_conn: Connection | str = "dst", dst_auth: dict | None = None) -> tuple[str, list[str]]:
        """Generate a temporary rclone config file. Handles both mount and transfer cases.
        Uses key_pem where supported to avoid extra temp files.
        """
        temp_files = []
        
        async def _prep_lines(conn, auth, prefix):
            lines = [
                f"[{prefix}]",
                "type = sftp",
                f"host = {conn.hostname}",
                f"port = {conn.port or 22}",
                f"user = {conn.username or 'root'}",
            ]
            
            if "password" in auth and auth["password"]:
                obs = await self._obscure_password(auth["password"])
                lines.append(f"pass = {obs}")
            
            if "key_path" in auth and auth["key_path"]:
                lines.append(f"key_file = {auth['key_path']}")
            elif "private_key_pem" in auth and auth["private_key_pem"]:
                pem_data = auth["private_key_pem"]
                if isinstance(pem_data, SecureBytes):
                    pem_str = pem_data.unsafe_get_str()
                else:
                    pem_str = pem_data.decode() if isinstance(pem_data, bytes) else pem_data
                
                # Format PEM for rclone config (indented)
                formatted_pem = pem_str.strip().replace("\n", "\n    ")
                lines.append(f"key_pem = {formatted_pem}")
                
            if "key_passphrase" in auth and auth["key_passphrase"]:
                 obs = await self._obscure_password(auth["key_passphrase"])
                 lines.append(f"key_file_pass = {obs}")
                 
            return lines

        final_lines = []
        if dst_auth is None:
            # Single remote (mount case)
            # If dst_conn is a string, it's our prefix name
            prefix = dst_conn if isinstance(dst_conn, str) else "mount_remote"
            final_lines.extend(await _prep_lines(src_conn, src_auth, prefix))
        else:
            # Dual remote (transfer case)
            final_lines.extend(await _prep_lines(src_conn, src_auth, "src"))
            final_lines.extend([""])
            final_lines.extend(await _prep_lines(dst_conn, dst_auth, "dst"))
        
        conf_fd, conf_path = tempfile.mkstemp(prefix="sentinel_rclone_conf_")
        with os.fdopen(conf_fd, 'w') as f:
            f.write("\n".join(final_lines) + "\n")
        
        os.chmod(conf_path, 0o600)
        return conf_path, temp_files

    def unmount_all(self):
        """Cleanly unmount all existing mounts."""
        # Use list to avoid "dictionary changed size" if monitor tasks pop during loop
        items = list(self._active_mounts.items())
        for conn_id, data in items:
            proc = data["proc"]
            config_path = data.get("config_path")
            if proc.returncode is None:
                proc.terminate()
            if config_path and os.path.exists(config_path):
                try: os.remove(config_path)
                except: pass
                
            mount_path = self.get_mount_path(conn_id)
            # Try to force unmount to prevent system hangs
            try:
                import subprocess
                subprocess.run(["fusermount3", "-u", mount_path], check=False, stderr=subprocess.DEVNULL)
            except: pass
        
        self._active_mounts.clear()

