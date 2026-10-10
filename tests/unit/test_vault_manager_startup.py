# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for VaultManager startup and keyring fallback behaviors."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import pytest

from services.vault_manager import VaultManager
from vault.secure_vault import SecureVault
from utils.secure import SecureBytes


class TestVaultManagerStartup:
    """Test VaultManager startup logic to ensure data is never erased automatically."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        VaultManager._instance = None
        yield
        VaultManager._instance = None

    def test_startup_uninitialized_returns_false_without_erasing(self, tmp_path: Path) -> None:
        """When the vault is not initialized, startup() returns False without auto-creating anything."""
        db_path = tmp_path / "test_vault.db"
        with patch("vault.secure_vault._default_vault_path", return_value=db_path), \
             patch("services.vault_manager.load_master_key", return_value=None):
            
            vm = VaultManager()
            assert not vm.is_initialized
            assert not vm.is_unlocked

            # startup() should return False and NOT initialize the vault
            res = vm.startup()
            assert res is False
            assert not vm.is_initialized
            assert not vm.is_unlocked

    def test_startup_keyring_failure_does_not_destroy_vault(self, tmp_path: Path) -> None:
        """When vault is initialized with data, but keyring returns None or invalid key,
        startup() MUST NOT destroy the vault! It should simply return False.
        """
        db_path = tmp_path / "test_vault.db"
        vault = SecureVault(path=db_path)
        vault.open()
        pwd = SecureBytes("StrongMasterPass123!")
        vault.initialize(pwd)
        vault.store_password("secret_item", "Test Label", SecureBytes("supersecret"))
        vault.close()

        # Now simulate VaultManager startup with keyring returning None (e.g. headless or locked keyring)
        with patch("services.vault_manager.load_master_key", return_value=None):
            vm = VaultManager()
            vm._vault = SecureVault(path=db_path)
            vm._vault.open()

            assert vm.is_initialized
            assert not vm.is_unlocked

            # Execute startup
            res = vm.startup()
            assert res is False
            assert vm.is_initialized  # CRITICAL: Vault must still be initialized!
            assert not vm.is_unlocked

            # Verify data can still be unlocked with original password
            assert vm.unlock(pwd) is True
            secret = vm._vault.get_password("secret_item")
            assert secret is not None
            assert secret.unsafe_get_str() == "supersecret"
