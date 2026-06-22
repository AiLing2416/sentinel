# SPDX-License-Identifier: GPL-3.0-or-later

"""Automatic migration tool from connections.db (unencrypted) to secure_vault.db (encrypted)."""

import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


def migrate_if_needed() -> None:
    """Migrate connection metadata from unencrypted SQLite to encrypted secure vault."""
    from services.vault_manager import VaultManager
    from models.connection import Connection
    from models.connection_group import ConnectionGroup
    from models.forward_rule import ForwardRule

    vm = VaultManager.get()
    if not vm.is_unlocked:
        logger.debug("Migration: Vault is locked, skipping migration check.")
        return

    data_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    legacy_path = Path(data_dir) / "sentinel" / "connections.db"

    if not legacy_path.exists():
        logger.debug("Migration: No legacy connections.db found.")
        return

    logger.info("Migration: Found legacy connections.db. Starting migration...")
    try:
        legacy_conn = sqlite3.connect(str(legacy_path))
        legacy_conn.row_factory = sqlite3.Row

        # 1. Migrate meta settings (except schema_version)
        try:
            rows_meta = legacy_conn.execute("SELECT key, value FROM meta").fetchall()
            for r in rows_meta:
                if r["key"] != "schema_version":
                    vm._vault._conn.execute(
                        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
                        (r["key"], r["value"])
                    )
        except Exception as e:
            logger.warning("Migration: Failed to migrate metadata settings: %s", e)

        # 2. Migrate groups
        try:
            rows_groups = legacy_conn.execute("SELECT * FROM groups").fetchall()
            for r in rows_groups:
                group = ConnectionGroup(
                    id=r["id"],
                    name=r["name"],
                    parent_id=r["parent_id"],
                    sort_order=r["sort_order"] or 0,
                    color=r["color"]
                )
                vm.store_group(group)
        except Exception as e:
            logger.warning("Migration: Failed to migrate connection groups: %s", e)

        # 3. Migrate connections
        try:
            rows_conns = legacy_conn.execute("SELECT * FROM connections").fetchall()
            for r in rows_conns:
                conn = Connection.from_dict(dict(r))
                vm.store_connection(conn)
        except Exception as e:
            logger.warning("Migration: Failed to migrate connections: %s", e)

        # 4. Migrate forward rules
        try:
            rows_rules = legacy_conn.execute("SELECT * FROM forward_rules").fetchall()
            for r in rows_rules:
                rule = ForwardRule.from_dict(dict(r))
                vm.store_forward_rule(rule)
        except Exception as e:
            logger.warning("Migration: Failed to migrate port forwarding rules: %s", e)

        # 5. Migrate known_hosts
        try:
            rows_hosts = legacy_conn.execute("SELECT * FROM known_hosts").fetchall()
            for r in rows_hosts:
                vm._vault._conn.execute(
                    """INSERT OR REPLACE INTO known_hosts
                       (hostname, port, key_type, fingerprint, first_seen, last_seen, trusted)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (r["hostname"], r["port"], r["key_type"], r["fingerprint"],
                     r["first_seen"], r["last_seen"], r["trusted"])
                )
        except Exception as e:
            logger.warning("Migration: Failed to migrate known hosts: %s", e)

        vm._vault._conn.commit()
        legacy_conn.close()

        # Rename to backup
        backup_path = legacy_path.with_suffix(".db.bak")
        if backup_path.exists():
            os.remove(str(backup_path))
        os.rename(str(legacy_path), str(backup_path))
        logger.info("Migration: Data migrated successfully. Legacy connections.db backed up to %s", backup_path)

    except Exception as e:
        logger.error("Migration: Critical migration error: %s", e)
