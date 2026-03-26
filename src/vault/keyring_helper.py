# SPDX-License-Identifier: GPL-3.0-or-later

"""Keyring helper for Sentinel SecureVault.

This module handles ONE simple job: storing and retrieving the raw 32-byte
master key from GNOME Keyring / libsecret, so the user is not prompted for
a password every time the app starts.

If libsecret is unavailable (Flatpak without portal, or headless), all
operations silently fail and return None — the vault simply asks for the
password on every launch.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_SCHEMA_NAME = "org.sentinel.Credentials"
_LEGACY_SCHEMA_NAME = "org.sentinel.VaultKey"
_ATTRIBUTE_ACCOUNT = "account"
_SECRET_LABEL_PREFIX = "Sentinel: "

# Try to import libsecret
try:
    import gi
    gi.require_version("Secret", "1")
    from gi.repository import Secret as _Secret
    _LIBSECRET_OK = True
except Exception:
    _Secret = None  # type: ignore[assignment]
    _LIBSECRET_OK = False


# Static schema definition to ensuring consistency between store and lookup
_SCHEMA = None

def _get_schema():
    global _SCHEMA
    if not _LIBSECRET_OK:
        return None
    if _SCHEMA is None:
        _SCHEMA = _Secret.Schema.new(
            _SCHEMA_NAME,
            _Secret.SchemaFlags.NONE,
            {_ATTRIBUTE_ACCOUNT: _Secret.SchemaAttributeType.STRING},
        )
    return _SCHEMA


def save_secret(account: str, secret: str | bytes, label: str | None = None) -> bool:
    """Save a secret into GNOME Keyring for a specific account.
    Returns True on success.
    """
    if not _LIBSECRET_OK:
        logger.debug("KeyringHelper: libsecret unavailable, skip save.")
        return False
    try:
        from base64 import b64encode
        schema = _get_schema()
        
        # If it's bytes (like our raw master key), we B64 it. 
        # If it's a string (like Bitwarden password), we store it directly if possible,
        # but for consistency and to match old master key logic, we B64 it if it's bytes.
        # Actually, let's keep it simple: if it's bytes, B64 it.
        if isinstance(secret, bytes):
            value = b64encode(secret).decode()
        else:
            value = secret

        store_label = label or f"{_SECRET_LABEL_PREFIX}{account}"
        
        ok = _Secret.password_store_sync(
            schema,
            {_ATTRIBUTE_ACCOUNT: account},
            _Secret.COLLECTION_DEFAULT,
            store_label,
            value,
            None,
        )
        
        if ok:
            logger.info("KeyringHelper: Secret for '%s' stored successfully.", account)
        else:
            logger.error("KeyringHelper: password_store_sync failed for '%s'.", account)
        return ok
    except Exception as e:
        logger.error("KeyringHelper: Failed to save secret for '%s': %s", account, e)
        return False


def load_secret(account: str, is_bytes: bool = False) -> str | bytes | None:
    """Load a secret from GNOME Keyring. Returns string/bytes or None."""
    if not _LIBSECRET_OK:
        logger.debug("KeyringHelper: libsecret unavailable, skip load.")
        return None
    try:
        from base64 import b64decode
        schema = _get_schema()
        value = _Secret.password_lookup_sync(
            schema,
            {_ATTRIBUTE_ACCOUNT: account},
            None,
        )
        if value:
            logger.debug("KeyringHelper: Found secret for '%s' in new schema.", account)
            if is_bytes:
                return b64decode(value)
            return value
        
        # Fallback for "master" key: try old schema if new one fails
        if account == "master":
            logger.debug("KeyringHelper: Master key NOT found in new schema, searching legacy...")
            try:
                legacy_schema = _Secret.Schema.new(
                    _LEGACY_SCHEMA_NAME,
                    _Secret.SchemaFlags.NONE,
                    {_ATTRIBUTE_ACCOUNT: _Secret.SchemaAttributeType.STRING},
                )
                old_value = _Secret.password_lookup_sync(
                    legacy_schema,
                    {_ATTRIBUTE_ACCOUNT: account},
                    None,
                )
                if old_value:
                    logger.info("KeyringHelper: Found legacy master key. Migrating to new schema...")
                    if is_bytes:
                        res = b64decode(old_value)
                        if save_master_key(res):
                            # SUCCESS! Now delete the old one to avoid duplicates
                            _Secret.password_clear_sync(legacy_schema, {_ATTRIBUTE_ACCOUNT: account}, None)
                            logger.info("KeyringHelper: Legacy master key migrated and cleared.")
                        return res
                    else:
                        if save_secret("master", old_value):
                             _Secret.password_clear_sync(legacy_schema, {_ATTRIBUTE_ACCOUNT: account}, None)
                             logger.info("KeyringHelper: Legacy master key migrated and cleared.")
                        return old_value
            except Exception as le:
                logger.debug("KeyringHelper: Legacy lookup failed or schema missing: %s", le)

        return None
    except Exception as e:
        logger.info("KeyringHelper: No secret found for '%s': %s", account, e)
        return None


def delete_secret(account: str) -> bool:
    """Remove a secret from GNOME Keyring. Returns True on success."""
    if not _LIBSECRET_OK:
        return False
    try:
        schema = _get_schema()
        ok = _Secret.password_clear_sync(
            schema,
            {_ATTRIBUTE_ACCOUNT: account},
            None,
        )
        logger.debug("KeyringHelper: Secret for '%s' cleared.", account)
        return ok
    except Exception as e:
        logger.error("KeyringHelper: Failed to clear secret for '%s': %s", account, e)
        return False


# ── Legacy Compatibility Wrappers ───────────────────────────────

def save_master_key(raw_key: bytes) -> bool:
    return save_secret("master", raw_key, label="Sentinel Vault Master Key")


def load_master_key() -> bytes | None:
    res = load_secret("master", is_bytes=True)
    return res if isinstance(res, (bytes, bytearray)) else None


def clear_master_key() -> bool:
    return delete_secret("master")


def is_available() -> bool:
    """Return True if GNOME Keyring / libsecret is usable."""
    return _LIBSECRET_OK
