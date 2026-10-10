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

    def test_startup_uninitialized_auto_generates_random_key_and_unlocks(self, tmp_path: Path) -> None:
        """When the vault is not initialized, startup() generates a random key,
        saves it to keyring, and transparently unlocks the vault.
        """
        db_path = tmp_path / "test_vault.db"
        keyring_store: dict[str, bytes] = {}

        def mock_save_master_key(raw_key: bytes) -> bool:
            keyring_store["master"] = bytes(raw_key)
            return True

        def mock_load_master_key() -> bytes | None:
            return keyring_store.get("master")

        with patch("vault.secure_vault._default_vault_path", return_value=db_path), \
             patch("services.vault_manager.save_master_key", side_effect=mock_save_master_key), \
             patch("services.vault_manager.load_master_key", side_effect=mock_load_master_key):

            vm = VaultManager()
            assert not vm.is_initialized
            assert not vm.is_unlocked

            # startup() should auto-initialize and return True
            res = vm.startup()
            assert res is True
            assert vm.is_initialized
            assert vm.is_unlocked
            assert "master" in keyring_store
            assert len(keyring_store["master"]) == 32

            # Simulate restart: on next startup with key in keyring, it unlocks cleanly
            vm.lock_session_only()
            assert not vm.is_unlocked
            assert vm.startup() is True
            assert vm.is_unlocked

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

    def test_master_password_envelope_and_keyring_fallback(self, tmp_path: Path) -> None:
        """Test full lifecycle:
        1. Initialize with Master Password -> Master Key saved to Keyring.
        2. Auto-unlock with Keyring succeeds.
        3. If Keyring is cleared/lost, unlock with Master Password recovers and re-saves to Keyring.
        """
        db_path = tmp_path / "test_vault.db"
        keyring_store: dict[str, bytes] = {}

        def mock_save_master_key(raw_key: bytes) -> bool:
            keyring_store["master"] = bytes(raw_key)
            return True

        def mock_load_master_key() -> bytes | None:
            return keyring_store.get("master")

        with patch("vault.secure_vault._default_vault_path", return_value=db_path), \
             patch("services.vault_manager.save_master_key", side_effect=mock_save_master_key), \
             patch("services.vault_manager.load_master_key", side_effect=mock_load_master_key):

            vm = VaultManager()
            pwd = SecureBytes("MySuperSecret1234")
            vm.initialize(pwd)

            # Check that master key was saved to keyring
            assert "master" in keyring_store
            assert len(keyring_store["master"]) == 32
            vm._vault.store_password("p1", "Label", SecureBytes("pass_val"))
            vm.lock_session_only()
            assert not vm.is_unlocked

            # 2. Auto-unlock via Keyring
            assert vm.startup() is True
            assert vm.is_unlocked
            val = vm._vault.get_password("p1")
            assert val is not None
            assert val.unsafe_get_str() == "pass_val"

            # 3. Simulate Keyring cleared / lost
            keyring_store.clear()
            vm.lock_session_only()
            assert not vm.is_unlocked

            # startup() cannot auto-unlock now
            assert vm.startup() is False
            assert not vm.is_unlocked

            # Manual unlock with Master Password succeeds and heals Keyring
            assert vm.unlock(pwd) is True
            assert vm.is_unlocked
            assert "master" in keyring_store  # Keyring re-populated!
            val2 = vm._vault.get_password("p1")
            assert val2 is not None
            assert val2.unsafe_get_str() == "pass_val"
