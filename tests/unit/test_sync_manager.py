# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for the SyncManager and configuration synchronization."""

from __future__ import annotations

from pathlib import Path
import pytest

from db.database import Database
from models.connection import Connection, AuthMethod
from models.connection_group import ConnectionGroup
from models.forward_rule import ForwardRule, ForwardType
from services.sync_manager import SyncManager


class TestSyncManager:
    """Test Suite for SyncManager core features."""

    def test_encryption_decryption_roundtrip(self) -> None:
        manager = SyncManager()
        data = {
            "version": 1,
            "connections": [
                {"id": "conn-1", "name": "Server A", "hostname": "localhost"}
            ]
        }
        
        # Encrypt
        encrypted = manager.encrypt_data(data)
        assert encrypted != ""
        assert isinstance(encrypted, str)
        assert "conn-1" not in encrypted  # Should be obfuscated

        # Decrypt
        decrypted = manager.decrypt_data(encrypted)
        assert decrypted == data
        assert decrypted["version"] == 1
        assert len(decrypted["connections"]) == 1
        assert decrypted["connections"][0]["name"] == "Server A"

    def test_serialization(self, tmp_path: Path) -> None:
        db_path = tmp_path / "sync_test.db"
        db = Database(path=db_path)
        db.open()

        # Insert sample connection group
        group = ConnectionGroup(name="Production")
        db.save_group(group)

        # Insert sample connection
        conn = Connection(
            name="Prod Web",
            hostname="10.0.0.1",
            group_id=group.id,
            auth_method=AuthMethod.PASSWORD
        )
        db.save_connection(conn)

        # Insert forward rule
        rule = ForwardRule(
            connection_id=conn.id,
            type=ForwardType.LOCAL,
            bind_port=8080,
            remote_host="127.0.0.1",
            remote_port=80
        )
        db.save_forward_rule(rule)
        db.close()

        # Serialize
        manager = SyncManager(db_path=db_path)
        serialized = manager.serialize_local_config()

        assert serialized["version"] == 1
        assert len(serialized["groups"]) == 1
        assert serialized["groups"][0]["name"] == "Production"

        assert len(serialized["connections"]) == 1
        assert serialized["connections"][0]["name"] == "Prod Web"
        assert serialized["connections"][0]["hostname"] == "10.0.0.1"

        assert len(serialized["forward_rules"]) == 1
        assert serialized["forward_rules"][0]["bind_port"] == 8080

    def test_deserialization_and_merge(self, tmp_path: Path) -> None:
        db_path = tmp_path / "merge_test.db"
        # We start with an empty DB
        db = Database(path=db_path)
        db.open()
        assert len(db.list_connections()) == 0
        db.close()

        sync_data = {
            "version": 1,
            "groups": [
                {"id": "group-1", "name": "Staging", "parent_id": None, "sort_order": 0, "color": None}
            ],
            "connections": [
                {
                    "id": "conn-2",
                    "name": "Stage DB",
                    "hostname": "192.168.1.5",
                    "port": 22,
                    "username": "dbuser",
                    "auth_method": "key",
                    "key_path": "/path/to/key",
                    "vault_item_id": "bw-123",
                    "vault_item_name": "My BW Key",
                    "jump_host_id": None,
                    "group_id": "group-1",
                    "os_id": None,
                    "notes": "Some db stage notes",
                    "last_connected": None,
                    "created_at": "2026-06-23T00:00:00",
                    "agent_forwarding": 0,
                    "sort_order": 0
                }
            ],
            "forward_rules": [
                {
                    "id": "rule-1",
                    "connection_id": "conn-2",
                    "type": "local",
                    "bind_address": "localhost",
                    "bind_port": 5432,
                    "remote_host": "localhost",
                    "remote_port": 5432,
                    "enabled": 1,
                    "auto_start": 0
                }
            ]
        }

        # Run merge
        manager = SyncManager(db_path=db_path)
        manager.deserialize_and_merge(sync_data)

        # Verify DB contents
        db.open()
        conns = db.list_connections()
        groups = db.list_groups()
        rules = db.list_forward_rules()
        db.close()

        assert len(groups) == 1
        assert groups[0].id == "group-1"
        assert groups[0].name == "Staging"

        assert len(conns) == 1
        assert conns[0].id == "conn-2"
        assert conns[0].name == "Stage DB"
        assert conns[0].vault_item_id == "bw-123"
        assert conns[0].group_id == "group-1"

        assert len(rules) == 1
        assert rules[0].id == "rule-1"
        assert rules[0].connection_id == "conn-2"
        assert rules[0].bind_port == 5432
