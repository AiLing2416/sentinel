# SPDX-License-Identifier: GPL-3.0-or-later

"""Service for checking and installing application updates from GitHub Releases.

Specifically designed for Flatpak user-space installations.
"""

from __future__ import annotations

import asyncio
import configparser
import logging
import os
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.request
import json
from typing import Callable, Any

logger = logging.getLogger(__name__)

class UpdaterService:
    """Manages application updates checking and user-space Flatpak installation."""

    _instance: UpdaterService | None = None

    @classmethod
    def get(cls) -> UpdaterService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def is_flatpak(self) -> bool:
        """Check if the application is running inside a Flatpak sandbox."""
        return os.path.exists("/.flatpak-info")

    def is_user_installation(self) -> bool:
        """Check if this is a user-space Flatpak installation (vs system-wide)."""
        if not self.is_flatpak():
            return False
        try:
            config = configparser.ConfigParser()
            config.read("/.flatpak-info")
            app_path = config.get("Instance", "app-path", fallback="")
            if not app_path:
                return False
            # System-wide installations typically start with /var/lib/flatpak/
            # User installations are located in ~/.local/share/flatpak/ which resolves to /home/...
            if app_path.startswith("/var/lib/flatpak") or app_path.startswith("/var/"):
                return False
            return True
        except Exception as e:
            logger.warning("Failed to parse /.flatpak-info: %s", e)
            return False

    def get_variant(self) -> str:
        """Determine if we are running the 'full' or 'slim' variant."""
        # The 'full' variant bundles CJK fonts in /app/share/fonts/noto
        if os.path.isdir("/app/share/fonts/noto"):
            return "full"
        return "slim"

    def get_arch(self) -> str:
        """Determine system architecture mapping for GitHub release assets."""
        mach = platform.machine().lower()
        if mach in ("x86_64", "amd64"):
            return "amd64"
        elif mach in ("aarch64", "arm64"):
            return "arm64"
        return "amd64"  # Default fallback

    def parse_version(self, v_str: str) -> tuple[int, int, int, int, str]:
        """Parse version string into a comparable tuple.
        
        Format: (major, minor, patch, weight, suffix)
        Release weight is 1, pre-release weight is 0.
        """
        v_str = v_str.lstrip("v").strip()
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", v_str)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            suffix = match.group(4).strip()
            weight = 0 if suffix else 1
            return (major, minor, patch, weight, suffix)
        return (0, 0, 0, 0, "")

    def compare_versions(self, local_str: str, remote_str: str) -> int:
        """Compare local and remote version strings.
        
        Returns:
            -1 if local < remote (update available)
             1 if local > remote (beta/development version)
             0 if local == remote (up to date)
        """
        local_norm = local_str.lstrip("v").strip()
        remote_norm = remote_str.lstrip("v").strip()
        
        if local_norm == remote_norm:
            return 0
            
        local_tuple = self.parse_version(local_norm)
        remote_tuple = self.parse_version(remote_norm)
        
        # Compare major, minor, patch, weight
        if local_tuple[:4] < remote_tuple[:4]:
            return -1
        elif local_tuple[:4] > remote_tuple[:4]:
            return 1
            
        # If everything up to weight is equal, but strings still differ
        if local_tuple[4] != remote_tuple[4]:
            # e.g., local has suffix, remote doesn't
            if local_tuple[3] < remote_tuple[3]:
                return -1
            elif local_tuple[3] > remote_tuple[3]:
                return 1
        return 0

    async def check_update(self, current_version: str) -> dict[str, Any]:
        """Fetch latest release from GitHub API and compare versions."""
        url = "https://api.github.com/repos/AiLing2416/sentinel/releases/latest"
        
        def _fetch():
            req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-App-Updater"})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
            raise urllib.error.URLError("Failed to fetch update info")

        try:
            data = await asyncio.to_thread(_fetch)
            tag_name = data.get("tag_name", "")
            if not tag_name:
                return {"status": "error", "error_message": "Invalid API response: no tag_name"}
                
            latest_version = tag_name.lstrip("v")
            comparison = self.compare_versions(current_version, latest_version)
            
            # Find the download URL for the flatpak bundle matching our arch & variant
            assets = data.get("assets", [])
            download_url = None
            variant = self.get_variant()
            arch = self.get_arch()
            
            # Target asset name pattern, e.g., sentinel-amd64.flatpak or sentinel-full-amd64.flatpak
            target_name = f"sentinel-full-{arch}.flatpak" if variant == "full" else f"sentinel-{arch}.flatpak"
            for asset in assets:
                if asset.get("name") == target_name:
                    download_url = asset.get("browser_download_url")
                    break

            release_notes = data.get("body", "")
            
            if comparison < 0:
                return {
                    "status": "update_available",
                    "latest_version": latest_version,
                    "download_url": download_url,
                    "release_notes": release_notes,
                    "target_name": target_name
                }
            elif comparison > 0:
                return {
                    "status": "beta_version",
                    "latest_version": latest_version,
                    "release_notes": release_notes
                }
            else:
                return {
                    "status": "latest",
                    "latest_version": latest_version
                }
                
        except urllib.error.URLError as e:
            logger.error("Failed to connect to GitHub: %s", e)
            return {"status": "error", "error_message": "network_error"}
        except Exception as e:
            logger.error("Update check failed: %s", e)
            return {"status": "error", "error_message": str(e)}

    async def download_and_install(
        self, 
        download_url: str, 
        progress_callback: Callable[[float], None] | None = None
    ) -> None:
        """Download flatpak bundle to shared runtime directory and execute host update."""
        if not self.is_flatpak():
            raise RuntimeError("not_flatpak")
            
        if not self.is_user_installation():
            raise RuntimeError("not_user_installation")

        uid = os.getuid()
        # Flatpak gives access to xdg-run/app/io.github.ailing2416.sentinel which resolves to this:
        shared_dir = f"/run/user/{uid}/app/io.github.ailing2416.sentinel"
        os.makedirs(shared_dir, exist_ok=True)
        dest_path = os.path.join(shared_dir, "sentinel-update.flatpak")

        def _download():
            req = urllib.request.Request(download_url, headers={"User-Agent": "Sentinel-App-Updater"})
            with urllib.request.urlopen(req, timeout=20) as response:
                total_size = int(response.headers.get("content-length", 0))
                downloaded = 0
                block_size = 65536
                with open(dest_path, "wb") as f:
                    while True:
                        buffer = response.read(block_size)
                        if not buffer:
                            break
                        f.write(buffer)
                        downloaded += len(buffer)
                        if progress_callback and total_size > 0:
                            # Send progress fraction (0.0 to 1.0)
                            progress_callback(downloaded / total_size)

        try:
            # Download file in thread pool to prevent blocking asyncio loop
            await asyncio.to_thread(_download)
        except Exception as e:
            logger.error("Failed to download update bundle: %s", e)
            if os.path.exists(dest_path):
                os.remove(dest_path)
            raise RuntimeError(f"download_failed: {e}")

        # Run flatpak-spawn on host to install/update the bundle
        flatpak_spawn_bin = shutil.which("flatpak-spawn") or "/usr/bin/flatpak-spawn"
        
        # Install without bypassing credentials checks. Normal host-level install.
        cmd = [
            flatpak_spawn_bin,
            "--host",
            "flatpak",
            "install",
            "--user",
            "--assumeyes",
            dest_path
        ]
        
        try:
            # Execute installation on host
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace")
                logger.error("Flatpak installation on host failed: %s", err_msg)
                raise RuntimeError(err_msg.strip())
                
        finally:
            # Clean up the downloaded flatpak bundle
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except Exception as e:
                    logger.warning("Failed to clean up flatpak bundle: %s", e)
