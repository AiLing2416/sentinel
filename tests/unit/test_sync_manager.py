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

    def test_calculate_removals(self, tmp_path: Path) -> None:
        db_path = tmp_path / "removals_calc_test.db"
        db = Database(path=db_path)
        db.open()
        
        group = ConnectionGroup(id="group-to-delete", name="Group A")
        db.save_group(group)
        conn = Connection(id="conn-to-delete", name="Conn A", hostname="127.0.0.1", group_id="group-to-delete")
        db.save_connection(conn)
        rule = ForwardRule(id="rule-to-delete", connection_id="conn-to-delete", bind_port=9000, remote_host="10.0.0.2", remote_port=80)
        db.save_forward_rule(rule)
        db.close()
        
        incoming_data = {
            "version": 1,
            "groups": [],
            "connections": [],
            "forward_rules": []
        }
        
        manager = SyncManager(db_path=db_path)
        removals = manager.calculate_removals(incoming_data)
        
        assert len(removals) == 3
        assert any("Group A" in r for r in removals)
        assert any("Conn A" in r for r in removals)
        assert any("9000" in r for r in removals)

    def test_deserialize_and_merge_with_removals(self, tmp_path: Path) -> None:
        db_path = tmp_path / "removals_merge_test.db"
        db = Database(path=db_path)
        db.open()
        
        group = ConnectionGroup(id="g-1", name="Keep Group")
        db.save_group(group)
        group_del = ConnectionGroup(id="g-2", name="Delete Group")
        db.save_group(group_del)
        
        conn = Connection(id="c-1", name="Keep Conn", hostname="localhost")
        db.save_connection(conn)
        conn_del = Connection(id="c-2", name="Delete Conn", hostname="127.0.0.1")
        db.save_connection(conn_del)
        db.close()
        
        incoming_data = {
            "version": 1,
            "groups": [
                {"id": "g-1", "name": "Keep Group", "parent_id": None, "sort_order": 0, "color": None}
            ],
            "connections": [
                {
                    "id": "c-1",
                    "name": "Keep Conn",
                    "hostname": "localhost",
                    "port": 22,
                    "username": "user",
                    "auth_method": "password",
                    "key_path": None,
                    "vault_item_id": None,
                    "vault_item_name": None,
                    "jump_host_id": None,
                    "group_id": None,
                    "os_id": None,
                    "notes": "",
                    "last_connected": None,
                    "created_at": "2026-06-23T00:00:00",
                    "agent_forwarding": 0,
                    "sort_order": 0
                }
            ],
            "forward_rules": []
        }
        
        manager = SyncManager(db_path=db_path)
        
        db.open()
        db.set_meta("sync_remove_missing", "true")
        db.close()
        
        manager.deserialize_and_merge(incoming_data, execute_removals=False)
        db.open()
        assert len(db.list_groups()) == 2
        assert len(db.list_connections()) == 2
        db.close()
        
        manager.deserialize_and_merge(incoming_data, execute_removals=True)
        db.open()
        groups = db.list_groups()
        conns = db.list_connections()
        db.close()
        
        assert len(groups) == 1
        assert groups[0].id == "g-1"
        assert len(conns) == 1
        assert conns[0].id == "c-1"

