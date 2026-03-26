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

    def _get_schema(self) -> Secret.Schema:
        return Secret.Schema.new(
            "org.sentinel.Connection",
            Secret.SchemaFlags.NONE,
            {
                "hostname": Secret.SchemaAttributeType.STRING,
                "username": Secret.SchemaAttributeType.STRING,
                "type": Secret.SchemaAttributeType.STRING, # 'password' or 'ssh-key'
            },
        )

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
                self._get_schema(),
                attributes,
                Secret.SearchFlags.ALL,
                None,
            )
            
            results = []
            for item in items:
                attrs = item.get_attributes()
                cred_type = attrs.get("type", "password")
                results.append(VaultCredential(
                    item_id=item.get_label(), # Use label as ID for lookup
                    name=item.get_label(),
                    username=attrs.get("username"),
                    has_password=(cred_type == "password"),
                    has_ssh_key=(cred_type == "ssh-key")
                ))
            return results
        except Exception as e:
            logger.error(f"libsecret search failed: {e}")
            return []

    async def get_password(self, item_id: str) -> SecureBytes:
        if not self.is_available:
            raise RuntimeError("libsecret not available")
            
        try:
            # item_id is the label we used
            items = Secret.password_search_sync(
                self._get_schema(),
                {},
                Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK,
                None
            )
            for item in items:
                if item.get_label() == item_id:
                    secret = item.get_secret()
                    if secret:
                        return SecureBytes(secret.get_text())
            
            raise ValueError(f"Password item '{item_id}' not found in keyring.")
        except Exception as e:
            logger.error(f"libsecret get_password failed: {e}")
            raise

    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial:
        if not self.is_available:
            raise RuntimeError("libsecret not available")

        # We store SSH keys as JSON in the secret field
        import json
        try:
            items = Secret.password_search_sync(
                self._get_schema(),
                {},
                Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK,
                None
            )
            for item in items:
                if item.get_label() == item_id:
                    secret_text = item.get_secret().get_text()
                    data = json.loads(secret_text)
                    return SSHKeyMaterial(
                        private_key_pem=SecureBytes(data["private_key"]),
                        passphrase=SecureBytes(data["passphrase"]) if data.get("passphrase") else None
                    )
            raise ValueError(f"SSH Key item '{item_id}' not found in keyring.")
        except Exception as e:
            logger.error(f"libsecret get_ssh_key failed: {e}")
            raise

    async def store_password(self, hostname: str, username: str, label: str, password: str) -> str:
        if not self.is_available:
            raise RuntimeError("libsecret not available")
        
        attributes = {
            "hostname": hostname,
            "username": username,
            "type": "password"
        }
        
        Secret.password_store_sync(
            self._get_schema(),
            attributes,
            Secret.COLLECTION_DEFAULT,
            label,
            password,
            None
        )
        return label

    async def store_ssh_key(self, hostname: str, username: str, label: str, private_key: str, passphrase: str | None = None) -> str:
        if not self.is_available:
            raise RuntimeError("libsecret not available")

        import json
        data = {
            "private_key": private_key,
            "passphrase": passphrase
        }
        
        attributes = {
            "hostname": hostname,
            "username": username,
            "type": "ssh-key"
        }
        
        Secret.password_store_sync(
            self._get_schema(),
            attributes,
            Secret.COLLECTION_DEFAULT,
            label,
            json.dumps(data),
            None
        )
        return label

    async def store_connection_config(self, config: dict) -> str:
        # For libsecret, we can just store the whole dict as JSON
        import json
        label = f"Sentinel: {config.get('name', 'Unnamed')}"
        
        attributes = {
            "hostname": config.get("hostname", ""),
            "username": config.get("username", ""),
            "type": "connection-config"
        }
        
        Secret.password_store_sync(
            self._get_schema(),
            attributes,
            Secret.COLLECTION_DEFAULT,
            label,
            json.dumps(config),
            None
        )
        return label

    async def retrieve_connection_configs(self) -> list[dict]:
        if not self.is_available:
            return []
        
        import json
        try:
            items = Secret.password_search_sync(
                self._get_schema(),
                {"type": "connection-config"},
                Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK,
                None
            )
            
            results = []
            for item in items:
                secret_text = item.get_secret().get_text()
                results.append(json.loads(secret_text))
            return results
        except Exception as e:
            logger.error(f"libsecret retrieve_configs failed: {e}")
            return []
