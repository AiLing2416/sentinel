# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for SecureVault batch listing methods."""

from __future__ import annotations

from pathlib import Path
import pytest

from models.connection import AuthMethod, Connection
from models.forward_rule import ForwardRule, ForwardType
from utils.secure import SecureBytes
from vault.secure_vault import SecureVault


class TestSecureVaultBatchListing:
    """Test batch querying and decoding in list_connections, list_forward_rules, list_global_keys."""

    def test_batch_listing_all_types(self, tmp_path: Path) -> None:
        db_path = tmp_path / "batch_vault.db"
        vault = SecureVault(path=db_path)
        vault.open()
        pwd = SecureBytes("SuperSafe123456!")
        vault.initialize(pwd)

        # 1. Populate multiple connections
        for i in range(5):
            c = Connection(
                id=f"conn_{i}",
                name=f"Connection {i}",
                hostname=f"host{i}.example.com",
                port=2200 + i,
                username=f"user{i}",
                auth_method=AuthMethod.KEY,
            )
            vault.store_connection(c)

        conns = vault.list_connections()
        assert len(conns) == 5
        conn_ids = {c.id for c in conns}
        assert conn_ids == {f"conn_{i}" for i in range(5)}
        for c in conns:
            assert c.hostname.endswith(".example.com")

        # 2. Populate multiple forward rules
        for i in range(4):
            rule = ForwardRule(
                id=f"rule_{i}",
                connection_id="conn_0",
                type=ForwardType.LOCAL,
                bind_address="127.0.0.1",
                bind_port=8080 + i,
                remote_host="localhost",
                remote_port=80 + i,
                enabled=True,
                auto_start=(i % 2 == 0),
            )
            vault.store_forward_rule(rule)

        rules = vault.list_forward_rules()
        assert len(rules) == 4
        rule_ids = {r.id for r in rules}
        assert rule_ids == {f"rule_{i}" for i in range(4)}

        # 3. Populate multiple global keys
        for i in range(3):
            vault.store_global_key(
                item_id=f"gkey_{i}",
                label=f"Key {i}",
                private_key_pem=SecureBytes(f"FAKE_PEM_{i}"),
                public_key_openssh=f"ssh-ed25519 AAAAC3... key{i}",
                key_type="ed25519",
                fingerprint=f"SHA256:fingerprint_{i}",
                passphrase=SecureBytes(f"pass_{i}"),
            )

        keys = vault.list_global_keys()
        assert len(keys) == 3
        key_ids = {k["id"] for k in keys}
        assert key_ids == {f"gkey_{i}" for i in range(3)}
        for k in keys:
            assert k["key_type"] == "ed25519"
            assert k["private_key"].unsafe_get_str().startswith("FAKE_PEM_")

        vault.close()
