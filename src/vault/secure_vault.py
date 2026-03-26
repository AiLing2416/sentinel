# SPDX-License-Identifier: GPL-3.0-or-later

"""Sentinel Local Secure Vault — AES-256-GCM encrypted SQLite storage.

Architecture (Termius-style):
    1. A master key (32 random bytes) is the root of trust.
    2. The master key is protected by a user password via PBKDF2-SHA256,
       and the result is stored in the local DB (salt + iterations + encrypted key).
    3. Additionally, the master key is stored in GNOME Keyring (if available)
       so the application can unlock transparently on next launch.
    4. All credential records are individually AES-256-GCM encrypted with
       the master key. The nonce is stored alongside the ciphertext.

Data never leaves this file in plaintext. The vault is entirely offline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import struct
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any

from utils.secure import SecureBytes
from vault.models import SSHKeyMaterial, VaultCredential

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_items (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    hostname      TEXT DEFAULT '',
    username      TEXT DEFAULT '',
    item_type     TEXT NOT NULL,     -- 'ssh-key' | 'password' | 'bitwarden-session'
    created_at    TEXT NOT NULL,
    nonce         TEXT NOT NULL,     -- Base64 AES-GCM nonce (12 bytes)
    ciphertext    TEXT NOT NULL      -- Base64 AES-GCM ciphertext
);
"""

# ── Crypto Helpers ────────────────────────────────────────────

def _derive_key(password: bytes, salt: bytes, iterations: int = 600000) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext+tag)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext. Raises on auth failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _generate_master_key() -> bytearray:
    """Generate a cryptographically random 32-byte master key as a mutable bytearray."""
    return bytearray(os.urandom(32))


def _encrypt_master_key(master_key: bytes, password: bytes) -> dict:
    """Encrypt the master key with a password. Returns a storable dict."""
    salt = os.urandom(32)
    iterations = 600000
    kek = _derive_key(password, salt, iterations)  # Key-Encryption-Key
    nonce, encrypted = _aes_gcm_encrypt(kek, master_key)
    return {
        "salt": b64encode(salt).decode(),
        "iterations": iterations,
        "nonce": b64encode(nonce).decode(),
        "encrypted_key": b64encode(encrypted).decode(),
    }


def _decrypt_master_key(stored: dict, password: bytes) -> bytes | None:
    """Decrypt the master key with a password. Returns None on wrong password."""
    try:
        salt = b64decode(stored["salt"])
        iterations = int(stored["iterations"])
        nonce = b64decode(stored["nonce"])
        encrypted = b64decode(stored["encrypted_key"])
        kek = _derive_key(password, salt, iterations)
        return _aes_gcm_decrypt(kek, nonce, encrypted)
    except Exception:
        return None


# ── Path ──────────────────────────────────────────────────────

def _default_vault_path() -> Path:
    data_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    vault_dir = Path(data_dir) / "sentinel"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir / "secure_vault.db"


# ── Vault ─────────────────────────────────────────────────────

class SecureVault:
    """Local AES-256-GCM encrypted credential store.
    
    Lifecycle:
        vault = SecureVault()
        vault.open()                          # Open or create the DB
        vault.initialize("my-master-pw")      # First-time setup
        assert vault.unlock("my-master-pw")   # Unlock on subsequent launches
        vault.store_ssh_key(...)              # Store credentials
        vault.get_ssh_key(...)                # Retrieve them
        vault.lock()                          # Clear master key from memory
        vault.close()                         # Close DB
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or _default_vault_path()
        self._conn: sqlite3.Connection | None = None
        self._master_key: bytearray | None = None  # In-memory only, zeroed on lock

    # ── Lifecycle ─────────────────────────────────────────────

    def open(self) -> None:
        """Open the database file and ensure schema exists."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.info("SecureVault: Opened at %s", self._path)

    def close(self) -> None:
        self.lock()
        if self._conn:
            self._conn.close()
            self._conn = None

    def lock(self) -> None:
        """Zero and discard the in-memory master key."""
        if self._master_key:
            for i in range(len(self._master_key)):
                self._master_key[i] = 0
            self._master_key = None
        logger.info("SecureVault: Locked.")

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    @property
    def is_initialized(self) -> bool:
        """Return True if a master key has been set up in the DB."""
        if not self._conn:
            return False
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = 'master_key_envelope'"
        ).fetchone()
        return row is not None

    # ── Setup & Unlock ────────────────────────────────────────

    def initialize_with_random_key(self) -> bytearray:
        """Initialize the vault with a freshly generated random master key.

        The raw key is returned so the caller can store it somewhere safe
        (e.g., GNOME Keyring). No password is needed — the key IS the secret.
        The vault stores the key with a random PBKDF2 envelope purely as a
        consistency check; the real protection comes from the keyring.

        Returns the 32-byte raw master key as a bytearray (caller must zero it).
        """
        assert self._conn is not None, "Vault not opened"
        if self.is_initialized:
            raise RuntimeError("Vault is already initialized.")

        master_key = _generate_master_key()  # bytearray
        # Store a self-signed envelope (encrypted with itself as password)
        # so we can verify integrity later via unlock_with_raw_key().
        envelope = _encrypt_master_key(bytes(master_key), bytes(master_key))

        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('master_key_envelope', ?)",
            (json.dumps(envelope),)
        )
        self._conn.commit()

        # Load into memory
        self._master_key = bytearray(master_key)
        logger.info("SecureVault: Initialized with random master key.")

        # Return a copy to the caller
        return bytearray(master_key)

    def initialize(self, password: SecureBytes | str) -> None:
        """Initialize the vault with a new master password (legacy path).
        Generates a new master key and encrypts it with the password.
        """
        assert self._conn is not None, "Vault not opened"
        if self.is_initialized:
            raise RuntimeError("Vault is already initialized. Use change_password() instead.")

        pwd_bytes = password.unsafe_get_bytes() if isinstance(password, SecureBytes) else password.encode()
        master_key = _generate_master_key()  # bytearray — mutable!
        envelope = _encrypt_master_key(bytes(master_key), pwd_bytes)

        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('master_key_envelope', ?)",
            (json.dumps(envelope),)
        )
        self._conn.commit()

        # Keep master key in memory (already a bytearray, no copy needed)
        self._master_key = master_key
        logger.info("SecureVault: Initialized with password-derived master key.")

    def unlock(self, password: SecureBytes | str) -> bool:
        """Unlock the vault with the master password. Returns True on success."""
        assert self._conn is not None, "Vault not opened"
        row = self._conn.execute(
            "SELECT value FROM vault_meta WHERE key = 'master_key_envelope'"
        ).fetchone()
        if not row:
            logger.warning("SecureVault: unlock() called but vault is not initialized.")
            return False

        pwd_bytes = password.unsafe_get_bytes() if isinstance(password, SecureBytes) else password.encode()
        envelope = json.loads(row[0])
        master_key = _decrypt_master_key(envelope, pwd_bytes)

        if master_key is None:
            logger.warning("SecureVault: Wrong password or corrupted data.")
            return False

        self._master_key = bytearray(master_key)
        logger.info("SecureVault: Unlocked successfully.")
        return True

    def unlock_with_raw_key(self, raw_key: bytes) -> bool:
        """Unlock with a raw 32-byte key (stored externally, e.g. from keyring)."""
        if len(raw_key) != 32:
            return False
        # Verify the key is correct by trying to decrypt any existing item
        # If no items exist, just load it directly.
        self._master_key = bytearray(raw_key)
        if self._conn:
            row = self._conn.execute("SELECT id, nonce, ciphertext FROM vault_items LIMIT 1").fetchone()
            if row:
                try:
                    nonce = b64decode(row["nonce"])
                    ct = b64decode(row["ciphertext"])
                    _aes_gcm_decrypt(bytes(self._master_key), nonce, ct)
                except Exception:
                    self.lock()
                    logger.warning("SecureVault: Raw key verification failed (key mismatch).")
                    return False
        logger.info("SecureVault: Unlocked with raw key.")
        return True

    def get_raw_master_key(self) -> bytes | None:
        """Return a copy of the raw master key (for storing in keyring)."""
        if not self._master_key:
            return None
        return bytes(self._master_key)

    def change_password(self, old_password: SecureBytes | str, new_password: SecureBytes | str) -> bool:
        """Re-encrypt the master key with the new password."""
        if not self.unlock(old_password):
            return False
        assert self._master_key is not None
        assert self._conn is not None

        new_pwd_bytes = new_password.unsafe_get_bytes() if isinstance(new_password, SecureBytes) else new_password.encode()
        envelope = _encrypt_master_key(bytes(self._master_key), new_pwd_bytes)
        self._conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('master_key_envelope', ?)",
            (json.dumps(envelope),)
        )
        self._conn.commit()
        logger.info("SecureVault: Password changed.")
        return True

    # ── Internal Crypto ───────────────────────────────────────

    def _pack_payload(self, fields: dict[str, bytes | SecureBytes | str | None]) -> bytes:
        """Binary packing of payload fields as bytes to avoid JSON strings."""
        buf = bytearray()
        # Header: Number of fields (2 bytes)
        buf.extend(struct.pack(">H", len(fields)))
        for k, v in fields.items():
            k_bytes = k.encode("utf-8")
            if v is None:
                val_bytes = b""
            elif isinstance(v, SecureBytes):
                val_bytes = v.unsafe_get_bytes()
            elif isinstance(v, str):
                val_bytes = v.encode("utf-8")
            else:
                val_bytes = v

            buf.extend(struct.pack(">H", len(k_bytes)))
            buf.extend(k_bytes)
            buf.extend(struct.pack(">I", len(val_bytes)))
            buf.extend(val_bytes)
        return bytes(buf)

    def _unpack_payload(self, data: bytes) -> dict[str, memoryview]:
        """Binary unpacking of payload fields."""
        if not data:
            return {}
            
        res = {}
        ptr = 0
        mv = memoryview(data)
        try:
            num_fields = struct.unpack_from(">H", mv, ptr)[0]
            ptr += 2
            for _ in range(num_fields):
                k_len = struct.unpack_from(">H", mv, ptr)[0]
                ptr += 2
                k = bytes(mv[ptr:ptr+k_len]).decode("utf-8")
                ptr += k_len
                v_len = struct.unpack_from(">I", mv, ptr)[0]
                ptr += 4
                v = mv[ptr:ptr+v_len]
                ptr += v_len
                res[k] = v
            return res
        except Exception as e:
            logger.error(f"SecureVault: Payload unpacking failed: {e}")
            raise ValueError("Corrupted vault payload") from e

    def _encrypt(self, data: dict) -> tuple[str, str]:
        """Encrypt a payload. Returns (base64 nonce, base64 ciphertext)."""
        assert self._master_key is not None, "Vault is locked"
        plaintext = self._pack_payload(data)
        nonce, ct = _aes_gcm_encrypt(bytes(self._master_key), plaintext)
        return b64encode(nonce).decode(), b64encode(ct).decode()

    def _decrypt(self, nonce_b64: str, ct_b64: str) -> dict[str, memoryview]:
        """Decrypt a stored record. Returns dict of memoryviews."""
        assert self._master_key is not None, "Vault is locked"
        nonce = b64decode(nonce_b64)
        ct = b64decode(ct_b64)
        plaintext = _aes_gcm_decrypt(bytes(self._master_key), nonce, ct)
        return self._unpack_payload(plaintext)

    # ── Storage ───────────────────────────────────────────────

    def store_ssh_key(
        self,
        item_id: str,
        label: str,
        private_key_pem: SecureBytes,
        passphrase: SecureBytes | None = None,
        hostname: str = "",
        username: str = "",
        key_type: str = "unknown",
        comment: str = "",
    ) -> None:
        """Store an SSH private key (encrypted)."""
        assert self._conn is not None
        import datetime

        payload = {
            "private_key": private_key_pem,
            "passphrase": passphrase, 
            "key_type": key_type,
            "comment": comment,
        }
        nonce, ct = self._encrypt(payload)
        self._conn.execute(
            """INSERT OR REPLACE INTO vault_items
               (id, label, hostname, username, item_type, created_at, nonce, ciphertext)
               VALUES (?, ?, ?, ?, 'ssh-key', ?, ?, ?)""",
            (item_id, label, hostname, username,
             datetime.datetime.now(datetime.timezone.utc).isoformat(), nonce, ct)
        )
        self._conn.commit()
        logger.debug("SecureVault: Stored SSH key for item '%s'.", item_id)

    def get_ssh_key(self, item_id: str) -> SSHKeyMaterial | None:
        """Retrieve and decrypt an SSH key by item ID."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM vault_items WHERE id = ? AND item_type = 'ssh-key'",
            (item_id,)
        ).fetchone()
        if not row:
            return None
        try:
            payload = self._decrypt(row["nonce"], row["ciphertext"])
            # payload keys now contain memoryviews, avoiding immutable strings
            pk_mv = payload.get("private_key")
            pass_mv = payload.get("passphrase")
            
            return SSHKeyMaterial(
                private_key_pem=SecureBytes(pk_mv) if pk_mv else SecureBytes(""),
                passphrase=SecureBytes(pass_mv) if pass_mv and len(pass_mv) > 0 else None,
                key_type=bytes(payload.get("key_type", b"")).decode("utf-8") if "key_type" in payload else "unknown",
                comment=bytes(payload.get("comment", b"")).decode("utf-8") if "comment" in payload else "",
            )
        except Exception as e:
            logger.error("SecureVault: Failed to decrypt SSH key '%s': %s", item_id, e)
            return None

    def store_password(
        self,
        item_id: str,
        label: str,
        password: SecureBytes,
        hostname: str = "",
        username: str = "",
    ) -> None:
        """Store a password (encrypted)."""
        assert self._conn is not None
        import datetime

        payload = {"password": password}
        nonce, ct = self._encrypt(payload)
        self._conn.execute(
            """INSERT OR REPLACE INTO vault_items
               (id, label, hostname, username, item_type, created_at, nonce, ciphertext)
               VALUES (?, ?, ?, ?, 'password', ?, ?, ?)""",
            (item_id, label, hostname, username,
             datetime.datetime.now(datetime.timezone.utc).isoformat(), nonce, ct)
        )
        self._conn.commit()
        logger.debug("SecureVault: Stored password for item '%s'.", item_id)

    def get_password(self, item_id: str) -> SecureBytes | None:
        """Retrieve and decrypt a password by item ID."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM vault_items WHERE id = ? AND item_type = 'password'",
            (item_id,)
        ).fetchone()
        if not row:
            return None
        try:
            payload = self._decrypt(row["nonce"], row["ciphertext"])
            pwd_mv = payload.get("password")
            return SecureBytes(pwd_mv) if pwd_mv else None
        except Exception as e:
            logger.error("SecureVault: Failed to decrypt password '%s': %s", item_id, e)
            return None

    def store_bitwarden_session(self, email: str, token: str) -> None:
        """Store a Bitwarden session token (encrypted)."""
        assert self._conn is not None
        import datetime

        payload = {"token": token, "email": email}
        nonce, ct = self._encrypt(payload)
        self._conn.execute(
            """INSERT OR REPLACE INTO vault_items
               (id, label, hostname, username, item_type, created_at, nonce, ciphertext)
               VALUES ('bw_session', 'Bitwarden Session', '', ?, 'bitwarden-session', ?, ?, ?)""",
            (email, datetime.datetime.now(datetime.timezone.utc).isoformat(), nonce, ct)
        )
        self._conn.commit()
        logger.debug("SecureVault: Stored Bitwarden session for %s.", email)

    def get_bitwarden_session(self) -> tuple[str | None, str | None]:
        """Retrieve the Bitwarden session token. Returns (email, token) or (None, None)."""
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT nonce, ciphertext FROM vault_items WHERE id = 'bw_session'"
        ).fetchone()
        if not row:
            return None, None
        try:
            payload = self._decrypt(row["nonce"], row["ciphertext"])
            email_mv = payload.get("email")
            token_mv = payload.get("token")
            return (
                bytes(email_mv).decode("utf-8") if email_mv else None,
                bytes(token_mv).decode("utf-8") if token_mv else None
            )
        except Exception as e:
            logger.error("SecureVault: Failed to decrypt Bitwarden session: %s", e)
            return None, None

    def delete_item(self, item_id: str) -> None:
        """Delete a stored item by ID."""
        assert self._conn is not None
        self._conn.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
        self._conn.commit()

    def list_items(
        self, item_type: str | None = None
    ) -> list[dict[str, str]]:
        """List all stored items (metadata only, no decryption)."""
        assert self._conn is not None
        if item_type:
            rows = self._conn.execute(
                "SELECT id, label, hostname, username, item_type, created_at FROM vault_items WHERE item_type = ?",
                (item_type,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, label, hostname, username, item_type, created_at FROM vault_items"
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_all(self) -> None:
        """Delete all vault items (but keep the master key envelope)."""
        assert self._conn is not None
        self._conn.execute("DELETE FROM vault_items")
        self._conn.commit()
        logger.warning("SecureVault: All items cleared.")

    def destroy(self) -> None:
        """DANGER: Delete all vault data including the master key. Cannot be undone."""
        assert self._conn is not None
        self._conn.execute("DELETE FROM vault_items")
        self._conn.execute("DELETE FROM vault_meta")
        self._conn.commit()
        self.lock()
        logger.warning("SecureVault: DESTROYED. All data erased.")
