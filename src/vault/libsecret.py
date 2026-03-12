# SPDX-License-Identifier: GPL-3.0-or-later

"""GNOME Keyring / libsecret backend implementation."""

from __future__ import annotations

import logging
import gi

try:
    gi.require_version("Secret", "1")
    from gi.repository import Secret
    LIBSECRET_AVAILABLE = True
except (ImportError, ValueError):
    LIBSECRET_AVAILABLE = False

from vault.base import VaultBackend
from vault.models import SSHKeyMaterial, VaultCredential
from utils.secure import SecureBytes

logger = logging.getLogger(__name__)


class LibsecretBackend(VaultBackend):
    """Local credentials backend using libsecret/GNOME Keyring."""

    @property
    def name(self) -> str:
        return "GNOME Keyring"

    @property
    def is_available(self) -> bool:
        return LIBSECRET_AVAILABLE

    async def login(self, email: str, password: SecureBytes | str, method: int | None = None, code: str | None = None) -> bool:
        # GNOME Keyring login is handled by the OS
        return True

    async def unlock(self, master_password: SecureBytes | str) -> bool:
        # GNOME Keyring is usually unlocked by the OS login
        return True

    async def lock(self) -> None:
        pass

    async def is_unlocked(self) -> bool:
        return True

    async def search_credentials(
        self, hostname: str, username: str | None = None
    ) -> list[VaultCredential]:
        if not self.is_available:
            return []

        attributes = {"hostname": hostname}
        if username:
            attributes["username"] = username

        try:
            items = Secret.password_search_sync(
                Secret.Schema.new(
                    "org.sentinel.Connection",
                    Secret.SchemaFlags.NONE,
                    {
                        "hostname": Secret.SchemaAttributeType.STRING,
                        "username": Secret.SchemaAttributeType.STRING,
                    },
                ),
                attributes,
                Secret.SearchFlags.ALL,
                None,
            )
            
            results = []
            for item in items:
                results.append(VaultCredential(
                    item_id=item.get_locked() or "libsecret-item", # simplified
                    name=item.get_label(),
                    username=item.get_attributes().get("username"),
                    has_password=True,
                    has_ssh_key=False
                ))
            return results
        except Exception as e:
            logger.error(f"libsecret search failed: {e}")
            return []

    async def get_password(self, item_id: str) -> SecureBytes:
        # For libsecret, we might need more info than just item_id if we want a direct lookup,
        # but for now let's assume we can find it. 
        # item_id in our search_credentials was a bit mocked.
        raise NotImplementedError("Direct password retrieval by item_id not implemented for libsecret yet.")

    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial:
        raise NotImplementedError("SSH Key storage in libsecret is not yet implemented.")

    async def store_connection_config(self, config: dict) -> str:
        raise NotImplementedError("libsecret config storage not implemented.")

    async def retrieve_connection_configs(self) -> list[dict]:
        return []
