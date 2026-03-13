# SPDX-License-Identifier: GPL-3.0-or-later

"""Abstract base class for password manager backends.

All credential access in Sentinel goes through this interface,
ensuring a clean separation between the app and any specific
password manager implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from vault.models import SSHKeyMaterial, VaultCredential


class VaultBackend(ABC):
    """Abstract interface for password manager / vault integration."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name (e.g., 'Bitwarden')."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Whether the backend CLI/library is installed and reachable."""
        ...

    @abstractmethod
    async def login(self, email: str, password: SecureBytes | str, method: int | None = None, code: SecureBytes | str | None = None) -> bool:
        """Log in to the vault provider. Returns True on success."""
        ...

    @abstractmethod
    async def unlock(self, master_password: SecureBytes | str) -> bool:
        ...

    @abstractmethod
    async def lock(self) -> None:
        """Lock the vault and securely erase the session token from memory."""
        ...

    @abstractmethod
    async def is_unlocked(self) -> bool:
        """Check whether the vault is currently unlocked."""
        ...

    @abstractmethod
    async def search_credentials(
        self, hostname: str, username: str | None = None
    ) -> list[VaultCredential]:
        """Search for credentials matching a host (and optionally user)."""
        ...

    @abstractmethod
    async def get_password(self, item_id: str) -> SecureBytes:
        """Retrieve a password from the vault by item ID."""
        ...

    @abstractmethod
    async def get_ssh_key(self, item_id: str) -> SSHKeyMaterial:
        """Retrieve an SSH private key from the vault by item ID."""
        ...

    @abstractmethod
    async def store_connection_config(self, config: dict) -> str:
        """Store a connection config as a Secure Note. Returns the vault item ID."""
        ...

    @abstractmethod
    async def retrieve_connection_configs(self) -> list[dict]:
        """Retrieve all Sentinel connection configs from the vault."""
        ...
