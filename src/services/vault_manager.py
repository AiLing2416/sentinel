# SPDX-License-Identifier: GPL-3.0-or-later

"""VaultManager — High-level service for SecureVault lifecycle management.

This is the single point of entry for all secure credential operations.
It handles:
  - Opening and closing the SecureVault DB
  - Auto-unlocking via GNOME Keyring (if available)
  - Prompting the user for a master password when auto-unlock fails
  - Storing Bitwarden session tokens for CLI reuse
  - Caching SSH keys fetched from Bitwarden into the local vault

Usage:
    vm = VaultManager.get()
    vm.startup()    # Call at app startup — auto-unlocks if possible

    # Check status
    if vm.is_unlocked:
        key = vm.get_ssh_key("some-item-id")

    # Explicit unlock (e.g. after user enters master password in UI)
    vm.unlock(master_password)

    # Store a retrieved Bitwarden key locally for caching
    vm.cache_ssh_key_from_bitwarden("bw-item-id", key_material)
"""

from __future__ import annotations

import logging
from typing import Callable

from vault.secure_vault import SecureVault
from vault.keyring_helper import save_master_key, load_master_key, clear_master_key
from vault.models import SSHKeyMaterial
from utils.secure import SecureBytes

logger = logging.getLogger(__name__)


class VaultManager:
    """Singleton service managing the local SecureVault."""

    _instance: VaultManager | None = None

    def __init__(self) -> None:
        self._vault = SecureVault()
        self._vault.open()

    @classmethod
    def get(cls) -> VaultManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Status ────────────────────────────────────────────────

    @property
    def is_unlocked(self) -> bool:
        return self._vault.is_unlocked

    @property
    def is_initialized(self) -> bool:
        return self._vault.is_initialized

    # ── Startup ───────────────────────────────────────────────

    def startup(self) -> bool:
        """Open and unlock the vault on application start. Fully automatic."""
        if self._vault.is_unlocked:
            return True

        # ── 1. Try to load key from Keyring FIRST (before DB operations potentially block) ──
        raw_key = load_master_key()
        if raw_key:
            if self._vault.unlock_with_raw_key(raw_key):
                logger.info("VaultManager: Auto-unlocked via GNOME Keyring.")
                return True
            else:
                logger.warning("VaultManager: Key from Keyring was rejected. SecureVault might be out of sync.")

        # ── 2. If not initialized, initialize now ──
        if not self._vault.is_initialized:
            logger.info("VaultManager: No secure vault found. Initializing...")
            try:
                # initialize_with_random_key() will open/write/commit to DB
                raw_key_ba = self._vault.initialize_with_random_key()
                key_to_save = bytes(raw_key_ba)
                
                # Zero out the sensitive info
                for i in range(len(raw_key_ba)):
                    raw_key_ba[i] = 0
                
                # Save to keyring
                if save_master_key(key_to_save):
                    logger.info("VaultManager: Random master key generated and saved to keyring.")
                else:
                    logger.error("VaultManager: Failed to save master key to keyring. Auto-unlock will not work.")
                
                return True
            except Exception as e:
                logger.error("VaultManager: Initialization failed: %s", e)
                return False

        # ── 3. Initialized but no key ──
        logger.warning("VaultManager: Keyring lookup failed and vault is already initialized.")
        return False

    # ── Unlock / Lock ─────────────────────────────────────────

    def initialize(self, password: SecureBytes | str) -> None:
        """Initialize a brand new vault with the given master password.
        Also saves the master key to GNOME Keyring for future auto-unlock.
        """
        self._vault.initialize(password)
        raw_key = self._vault.get_raw_master_key()
        if raw_key:
            save_master_key(raw_key)
            logger.info("VaultManager: New vault initialized. Master key saved to keyring.")

    def unlock(self, password: SecureBytes | str) -> bool:
        """Unlock the vault with the user-provided master password.
        On success, also saves the master key to keyring for next launch.
        """
        ok = self._vault.unlock(password)
        if ok:
            raw_key = self._vault.get_raw_master_key()
            if raw_key:
                save_master_key(raw_key)
        return ok

    def lock(self) -> None:
        """Lock the vault and clear the keyring entry (explicit user action)."""
        self._vault.lock()
        clear_master_key()
        logger.info("VaultManager: Vault locked. Keyring entry cleared.")

    def lock_session_only(self) -> None:
        """Lock the vault in-memory but keep the keyring entry.
        Use this for inactivity timeout (not for explicit logout).
        """
        self._vault.lock()
        logger.info("VaultManager: Vault locked (session only, keyring kept).")

    def change_password(
        self, old_password: SecureBytes | str, new_password: SecureBytes | str
    ) -> bool:
        """Change the vault master password."""
        ok = self._vault.change_password(old_password, new_password)
        if ok:
            raw_key = self._vault.get_raw_master_key()
            if raw_key:
                save_master_key(raw_key)
        return ok

    # ── SSH Key Cache ─────────────────────────────────────────

    def cache_ssh_key(
        self,
        item_id: str,
        label: str,
        key_material: SSHKeyMaterial,
        hostname: str = "",
        username: str = "",
    ) -> bool:
        """Cache an SSH key material into the local vault (e.g., fetched from Bitwarden).
        Returns False if vault is locked.
        """
        if not self._vault.is_unlocked:
            logger.warning("VaultManager: Cannot cache SSH key; vault is locked.")
            return False

        self._vault.store_ssh_key(
            item_id=item_id,
            label=label,
            private_key_pem=key_material.private_key_pem,
            passphrase=key_material.passphrase,
            hostname=hostname,
            username=username,
            key_type=key_material.key_type,
            comment=key_material.comment,
        )
        return True

    def get_cached_ssh_key(self, item_id: str) -> SSHKeyMaterial | None:
        """Retrieve a cached SSH key from the local vault."""
        if not self._vault.is_unlocked:
            return None
        return self._vault.get_ssh_key(item_id)

    # ── Password Cache ────────────────────────────────────────

    def cache_password(
        self,
        item_id: str,
        label: str,
        password: SecureBytes,
        hostname: str = "",
        username: str = "",
    ) -> bool:
        """Cache a password into the local vault."""
        if not self._vault.is_unlocked:
            return False
        self._vault.store_password(item_id, label, password, hostname, username)
        return True

    def get_cached_password(self, item_id: str) -> SecureBytes | None:
        """Retrieve a cached password from the local vault."""
        if not self._vault.is_unlocked:
            return None
        return self._vault.get_password(item_id)

    # ── Bitwarden Support ─────────────────────────────────────
    
    def save_bitwarden_password(self, password: SecureBytes | str) -> bool:
        """Save the Bitwarden master password to system keyring."""
        from vault import keyring_helper
        pwd = password.unsafe_get_str() if isinstance(password, SecureBytes) else password
        return keyring_helper.save_secret("bitwarden", pwd, label="Sentinel: Bitwarden Master Password")

    def get_bitwarden_password(self) -> str | None:
        """Retrieve the Bitwarden master password from system keyring."""
        from vault import keyring_helper
        res = keyring_helper.load_secret("bitwarden")
        return res if isinstance(res, str) else None

    def clear_bitwarden_password(self) -> bool:
        """Remove the Bitwarden master password from system keyring."""
        from vault import keyring_helper
        return keyring_helper.delete_secret("bitwarden")

    # ── Bitwarden Session ─────────────────────────────────────

    def save_bitwarden_session(self, email: str, token: str) -> bool:
        """Persist a Bitwarden CLI session token in the local vault."""
        if not self._vault.is_unlocked:
            logger.warning("VaultManager: Cannot save Bitwarden session; vault is locked.")
            return False
        self._vault.store_bitwarden_session(email, token)
        return True

    def get_bitwarden_session(self) -> tuple[str | None, str | None]:
        """Retrieve the stored Bitwarden session token. Returns (email, token)."""
        if not self._vault.is_unlocked:
            return None, None
        return self._vault.get_bitwarden_session()

    def clear_bitwarden_session(self) -> None:
        """Remove the stored Bitwarden session token."""
        if self._vault.is_unlocked:
            self._vault.delete_item("bw_session")

    # ── Management ────────────────────────────────────────────

    def list_cached_items(self, item_type: str | None = None) -> list[dict]:
        """List all cached items (no sensitive data exposed)."""
        if not self._vault.is_unlocked:
            return []
        return self._vault.list_items(item_type)

    def delete_item(self, item_id: str) -> None:
        """Delete a specific cached item."""
        if self._vault.is_unlocked:
            self._vault.delete_item(item_id)

    def destroy_vault(self) -> None:
        """DANGER: Destroy the entire vault. Clears keyring too."""
        self._vault.destroy()
        clear_master_key()
        logger.warning("VaultManager: Vault destroyed.")
