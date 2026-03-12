# SPDX-License-Identifier: GPL-3.0-or-later

"""Vault Service — Manages active password manager backends."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vault.bitwarden import BitwardenBackend
from vault.libsecret import LibsecretBackend

if TYPE_CHECKING:
    from vault.base import VaultBackend

logger = logging.getLogger(__name__)


class VaultService:
    """Service to coordinate between different vault backends."""

    _instance: VaultService | None = None

    def __init__(self) -> None:
        # We instantiate both to check availability
        self._backends: dict[str, VaultBackend] = {
            "bitwarden": BitwardenBackend(),
            "libsecret": LibsecretBackend()
        }
        
        # Determine default active backend
        if self._backends["bitwarden"].is_available:
            self._active_backend_name = "bitwarden"
        elif self._backends["libsecret"].is_available:
            self._active_backend_name = "libsecret"
        else:
            self._active_backend_name = None

    @classmethod
    def get(cls) -> VaultService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_backend(self, name: str) -> VaultBackend | None:
        return self._backends.get(name)

    @property
    def active_backend(self) -> VaultBackend | None:
        if not self._active_backend_name:
            return None
        return self._backends.get(self._active_backend_name)

    def set_active_backend(self, name: str) -> None:
        if name in self._backends:
            self._active_backend_name = name
        else:
            raise ValueError(f"Backend '{name}' is not available.")

    def get_available_backends(self) -> list[str]:
        return list(self._backends.keys())
