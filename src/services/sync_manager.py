# SPDX-License-Identifier: GPL-3.0-or-later

"""SyncManager — Core service for syncing connections, groups, and rules to Bitwarden notes."""

from __future__ import annotations
import json
import zlib
import hashlib
import logging
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db.database import Database
from models.connection import Connection
from models.connection_group import ConnectionGroup
from models.forward_rule import ForwardRule
from services.vault_service import VaultService

logger = logging.getLogger(__name__)


class SyncManager:
    """Manages secure configuration synchronization."""

    _instance: SyncManager | None = None

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._importing = False
        self._db_path = db_path

    @classmethod
    def get(cls) -> SyncManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _get_encryption_key(self) -> bytes:
        # Obfuscation key derived statically to allow decryption across different Sentinel installs
        return hashlib.sha256(b"SentinelSyncSecretKeyObfuscationSalt").digest()

    def encrypt_data(self, data: dict) -> str:
        """Compress/serialize and encrypt configuration dict using AES-256-GCM."""
        plaintext = json.dumps(data).encode("utf-8")
        compressed = zlib.compress(plaintext)
        key = self._get_encryption_key()
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, compressed, None)
        combined = nonce + ciphertext
        return b64encode(combined).decode("utf-8")

    def decrypt_data(self, payload_str: str) -> dict:
        """Decrypt AES-256-GCM data payload and load configuration dict."""
        combined = b64decode(payload_str.encode("utf-8"))
        if len(combined) < 12:
            raise ValueError("Encrypted sync payload is too short or malformed")
        nonce = combined[:12]
        ciphertext = combined[12:]
        key = self._get_encryption_key()
        decrypted = AESGCM(key).decrypt(nonce, ciphertext, None)
        
        try:
            plaintext = zlib.decompress(decrypted)
        except zlib.error:
            # Fallback for legacy uncompressed format
            plaintext = decrypted
            
        return json.loads(plaintext.decode("utf-8"))

    def serialize_local_config(self) -> dict:
        """Gather all connections, groups, and port forwarding rules into a standard dictionary."""
        db = Database(self._db_path)
        db.open()
        try:
            conns = db.list_connections()
            groups = db.list_groups()
            rules = db.list_forward_rules()

            return {
                "version": 1,
                "connections": [c.to_dict() for c in conns],
                "groups": [g.to_dict() for g in groups],
                "forward_rules": [r.to_dict() for r in rules]
            }
        finally:
            db.close()

    def deserialize_and_merge(self, data: dict) -> None:
        """Merge incoming sync dictionary into the local database (incremental merge)."""
        self._importing = True
        try:
            db = Database(self._db_path)
            db.open()
            try:
                # 1. Groups
                for g_dict in data.get("groups", []):
                    group = ConnectionGroup.from_dict(g_dict)
                    db.save_group(group)
                    
                # 2. Connections
                for c_dict in data.get("connections", []):
                    conn = Connection.from_dict(c_dict)
                    db.save_connection(conn)
                    
                # 3. Forward Rules
                for r_dict in data.get("forward_rules", []):
                    rule = ForwardRule.from_dict(r_dict)
                    db.save_forward_rule(rule)
            finally:
                db.close()
        finally:
            self._importing = False

    async def push_sync(self, item_id: str) -> None:
        """Push encrypted local configuration to the specified Bitwarden note."""
        vault = VaultService.get().get_backend("bitwarden")
        if not vault:
            raise RuntimeError("Bitwarden backend not available")
        
        await vault.sync()
        
        config_data = self.serialize_local_config()
        encrypted_payload = self.encrypt_data(config_data)
        
        # update_sync_note is added to Bitwarden class in bitwarden.py
        await vault.update_sync_note(item_id, encrypted_payload)
        logger.info(f"SyncManager: Successfully pushed config to Bitwarden Note '{item_id}'")

    async def pull_sync(self, item_id: str) -> None:
        """Pull and merge configuration from the specified Bitwarden note."""
        vault = VaultService.get().get_backend("bitwarden")
        if not vault:
            raise RuntimeError("Bitwarden backend not available")
        
        await vault.sync()
        
        # get_sync_note is added to Bitwarden class in bitwarden.py
        encrypted_payload = await vault.get_sync_note(item_id)
        if not encrypted_payload or not encrypted_payload.strip():
            logger.warning("SyncManager: Retrieved sync payload is empty. Nothing to pull.")
            return
        
        config_data = self.decrypt_data(encrypted_payload)
        self.deserialize_and_merge(config_data)
        logger.info(f"SyncManager: Successfully pulled and merged config from Bitwarden Note '{item_id}'")

    def trigger_auto_sync(self) -> None:
        """Check preferences and push local updates to Bitwarden asynchronously if enabled."""
        if self._importing:
            return

        db = Database(self._db_path)
        db.open()
        try:
            enabled = db.get_meta("sync_enabled") == "true"
            auto = db.get_meta("sync_auto") == "true"
            item_id = db.get_meta("sync_item_id")
        finally:
            db.close()

        if enabled and auto and item_id:
            from services.ssh_service import SSHService
            async def _do_auto_push():
                try:
                    await self.push_sync(item_id)
                except Exception as e:
                    logger.error(f"SyncManager: Background auto-sync failed: {e}")
            SSHService().engine.run_coroutine(_do_auto_push())
