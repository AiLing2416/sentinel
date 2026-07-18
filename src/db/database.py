# SPDX-License-Identifier: GPL-3.0-or-later

"""Database helper layer for Sentinel.

Now points to secure_vault.db and transparently routes sensitive connection
metadata, groups, and port forwarding rules to VaultManager for encryption,
while exposing unencrypted known_hosts and vault_meta.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

from models.connection import Connection, ValidationError
from models.connection_group import ConnectionGroup
from models.forward_rule import ForwardRule

logger = logging.getLogger(__name__)

# Legacy schema used ONLY in testing (custom paths) or during migration
_LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  TEXT REFERENCES groups(id) ON DELETE CASCADE,
    sort_order INTEGER DEFAULT 0,
    color      TEXT
);

CREATE TABLE IF NOT EXISTS connections (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    port          INTEGER NOT NULL DEFAULT 22,
    username      TEXT NOT NULL DEFAULT '',
    auth_method   TEXT NOT NULL DEFAULT 'key',
    key_path      TEXT,
    vault_item_id TEXT,
    jump_host_id  TEXT REFERENCES connections(id) ON DELETE SET NULL,
    group_id      TEXT REFERENCES groups(id) ON DELETE SET NULL,
    os_id         TEXT,
    notes         TEXT DEFAULT '',
    last_connected TEXT,
    created_at    TEXT NOT NULL,
    agent_forwarding INTEGER DEFAULT 0,
    sort_order    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS forward_rules (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    type          TEXT NOT NULL,
    bind_address  TEXT DEFAULT 'localhost',
    bind_port     INTEGER NOT NULL,
    remote_host   TEXT DEFAULT 'localhost',
    remote_port   INTEGER,
    enabled       INTEGER DEFAULT 1,
    auto_start    INTEGER DEFAULT 0
);
"""


def _default_db_path() -> Path:
    """Return XDG-compliant database path for secure_vault.db."""
    data_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    db_dir = Path(data_dir) / "sentinel"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "secure_vault.db"


class Database:
    """Synchronous SQLite database manager for Sentinel."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else _default_db_path()
        self._conn: sqlite3.Connection | None = None

    @property
    def path(self) -> Path:
        return self._path

    # ── Lifecycle ─────────────────────────────────────────────

    def open(self) -> None:
        """Open the database connection."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        
        # Ensure known_hosts table exists (unencrypted in secure_vault.db)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS known_hosts (
                hostname    TEXT NOT NULL,
                port        INTEGER NOT NULL,
                key_type    TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                trusted     INTEGER DEFAULT 0,
                PRIMARY KEY (hostname, port, key_type)
            );"""
        )
        self._conn.commit()

        # Apply legacy schema ONLY if running with a custom path (e.g. tests or migration source)
        if self._path != _default_db_path():
            self._conn.executescript(_LEGACY_SCHEMA)
            self._conn.commit()
            
            # Legacy migration support: add columns to connection if they do not exist
            cols = [col["name"] for col in self._conn.execute("PRAGMA table_info(connections)").fetchall()]
            if "os_id" not in cols:
                self._conn.execute("ALTER TABLE connections ADD COLUMN os_id TEXT")
                self._conn.commit()
            if "agent_forwarding" not in cols:
                self._conn.execute("ALTER TABLE connections ADD COLUMN agent_forwarding INTEGER DEFAULT 0")
                self._conn.commit()
            cols_fr = [col["name"] for col in self._conn.execute("PRAGMA table_info(forward_rules)").fetchall()]
            if "auto_start" not in cols_fr:
                self._conn.execute("ALTER TABLE forward_rules ADD COLUMN auto_start INTEGER DEFAULT 0")
                self._conn.commit()

        logger.info("Database opened: %s", self._path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("Database closed")

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not opened. Call open() first.")
        return self._conn

    # ── Meta / Settings ───────────────────────────────────────

    def set_meta(self, key: str, value: str) -> None:
        """Set a global app setting."""
        table = "vault_meta" if self._path == _default_db_path() else "meta"
        self._db.execute(
            f"INSERT OR REPLACE INTO {table} (key, value) VALUES (?, ?)",
            (key, value)
        )
        self._db.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        """Get a global app setting."""
        table = "vault_meta" if self._path == _default_db_path() else "meta"
        try:
            row = self._db.execute(
                f"SELECT value FROM {table} WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else default
        except sqlite3.OperationalError:
            return default

    # ── Connection CRUD ───────────────────────────────────────

    def save_connection(self, conn: Connection) -> None:
        """Insert or replace a connection configuration."""
        conn.validate()
        
        # Check for cyclic jump host configurations (DAG validation)
        if conn.jump_host_id:
            curr_id = conn.jump_host_id
            visited = set()
            while curr_id:
                if curr_id == conn.id or curr_id in visited:
                    raise ValidationError("Cyclic jump host reference detected")
                visited.add(curr_id)
                jump_host = self.get_connection(curr_id)
                if not jump_host:
                    break
                curr_id = jump_host.jump_host_id

        # Fallback to local SQLite database when a custom path is used (e.g. tests)
        if self._path != _default_db_path():
            data = conn.to_dict()
            self._db.execute(
                """INSERT OR REPLACE INTO connections (
                    id, name, hostname, port, username, auth_method, key_path, 
                    vault_item_id, jump_host_id, group_id, os_id, notes, 
                    last_connected, created_at, agent_forwarding, sort_order
                ) VALUES (
                    :id, :name, :hostname, :port, :username, :auth_method, :key_path,
                    :vault_item_id, :jump_host_id, :group_id, :os_id, :notes,
                    :last_connected, :created_at, :agent_forwarding, :sort_order
                )""",
                data,
            )
            self._db.commit()
            return

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if not vm.is_unlocked:
            raise RuntimeError("Cannot save connection: Local Vault is locked.")
        vm.store_connection(conn)

        try:
            from services.sync_manager import SyncManager
            SyncManager.get().trigger_auto_sync()
        except Exception as se:
            logger.debug("Failed to trigger auto sync: %s", se)

    def get_connection(self, conn_id: str) -> Connection | None:
        """Retrieve a connection by ID."""
        if self._path != _default_db_path():
            row = self._db.execute(
                "SELECT * FROM connections WHERE id = ?", (conn_id,)
            ).fetchone()
            return Connection.from_dict(dict(row)) if row else None

        from services.vault_manager import VaultManager
        return VaultManager.get().get_connection(conn_id)

    def list_connections(self, group_id: str | None = None) -> list[Connection]:
        """List all connections, optionally filtered by group."""
        if self._path != _default_db_path():
            if group_id is not None:
                rows = self._db.execute(
                    "SELECT * FROM connections WHERE group_id = ? ORDER BY sort_order, name",
                    (group_id,),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM connections ORDER BY sort_order, name"
                ).fetchall()
            return [Connection.from_dict(dict(r)) for r in rows]

        from services.vault_manager import VaultManager
        conns = VaultManager.get().list_connections()
        if group_id is not None:
            conns = [c for c in conns if c.group_id == group_id]
        conns.sort(key=lambda c: (c.sort_order, c.name.lower()))
        return conns

    def delete_connection(self, conn_id: str) -> bool:
        """Remove a connection by ID. Returns True if removed."""
        if self._path != _default_db_path():
            cur = self._db.execute("DELETE FROM connections WHERE id = ?", (conn_id,))
            self._db.commit()
            return cur.rowcount > 0

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if vm.is_unlocked:
            vm.delete_connection(conn_id)
            try:
                from services.sync_manager import SyncManager
                SyncManager.get().trigger_auto_sync()
            except Exception as se:
                logger.debug("Failed to trigger auto sync: %s", se)
            return True
        return False

    def search_connections(self, query: str) -> list[Connection]:
        """Search connections by name or hostname (case-insensitive)."""
        if self._path != _default_db_path():
            pattern = f"%{query}%"
            rows = self._db.execute(
                "SELECT * FROM connections WHERE name LIKE ? OR hostname LIKE ? "
                "ORDER BY sort_order, name",
                (pattern, pattern),
            ).fetchall()
            return [Connection.from_dict(dict(r)) for r in rows]

        from services.vault_manager import VaultManager
        conns = VaultManager.get().list_connections()
        query = query.strip().lower()
        if not query:
            return conns
        results = [
            c for c in conns 
            if query in c.name.lower() or query in c.hostname.lower()
        ]
        results.sort(key=lambda c: (c.sort_order, c.name.lower()))
        return results

    def delete_known_hosts(self, hostname: str, port: int) -> int:
        """Clear known hosts trust for a specific hostname and port.
        Returns the number of keys cleared.
        """
        cur = self._db.execute(
            "DELETE FROM known_hosts WHERE hostname = ? AND port = ?",
            (hostname, port)
        )
        self._db.commit()
        if cur.rowcount > 0:
            logger.debug("Cleared %d host keys for %s:%d", cur.rowcount, hostname, port)
        return cur.rowcount

    # ── Forward Rule CRUD ─────────────────────────────────────

    def save_forward_rule(self, rule: ForwardRule) -> None:
        """Insert or replace a port forwarding rule."""
        rule.validate()
        
        if self._path != _default_db_path():
            data = rule.to_dict()
            self._db.execute(
                """INSERT OR REPLACE INTO forward_rules (
                    id, connection_id, type, bind_address, bind_port,
                    remote_host, remote_port, enabled, auto_start
                ) VALUES (
                    :id, :connection_id, :type, :bind_address, :bind_port,
                    :remote_host, :remote_port, :enabled, :auto_start
                )""",
                data,
            )
            self._db.commit()
            return

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if not vm.is_unlocked:
            raise RuntimeError("Cannot save forward rule: Local Vault is locked.")
        vm.store_forward_rule(rule)

        try:
            from services.sync_manager import SyncManager
            SyncManager.get().trigger_auto_sync()
        except Exception as se:
            logger.debug("Failed to trigger auto sync: %s", se)

    def get_forward_rule(self, rule_id: str) -> ForwardRule | None:
        """Retrieve a forward rule by ID."""
        if self._path != _default_db_path():
            row = self._db.execute(
                "SELECT * FROM forward_rules WHERE id = ?", (rule_id,)
            ).fetchone()
            return ForwardRule.from_dict(dict(row)) if row else None

        from services.vault_manager import VaultManager
        return VaultManager.get().get_forward_rule(rule_id)

    def list_forward_rules(self, connection_id: str | None = None) -> list[ForwardRule]:
        """List all forward rules, optionally filtered by connection."""
        if self._path != _default_db_path():
            if connection_id is not None:
                rows = self._db.execute(
                    "SELECT * FROM forward_rules WHERE connection_id = ? ORDER BY type, bind_port",
                    (connection_id,),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM forward_rules ORDER BY connection_id, type, bind_port"
                ).fetchall()
            return [ForwardRule.from_dict(dict(r)) for r in rows]

        from services.vault_manager import VaultManager
        rules = VaultManager.get().list_forward_rules()
        if connection_id is not None:
            rules = [r for r in rules if r.connection_id == connection_id]
        rules.sort(key=lambda r: (r.type.value, r.bind_port))
        return rules

    def delete_forward_rule(self, rule_id: str) -> bool:
        """Remove a forward rule by ID. Returns True if removed."""
        if self._path != _default_db_path():
            cur = self._db.execute("DELETE FROM forward_rules WHERE id = ?", (rule_id,))
            self._db.commit()
            return cur.rowcount > 0

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if vm.is_unlocked:
            vm.delete_forward_rule(rule_id)
            try:
                from services.sync_manager import SyncManager
                SyncManager.get().trigger_auto_sync()
            except Exception as se:
                logger.debug("Failed to trigger auto sync: %s", se)
            return True
        return False

    # ── Group CRUD ────────────────────────────────────────────

    def save_group(self, group: ConnectionGroup) -> None:
        """Insert or replace a connection group."""
        group.validate()
        
        if self._path != _default_db_path():
            data = group.to_dict()
            self._db.execute(
                """INSERT OR REPLACE INTO groups (
                    id, name, parent_id, sort_order, color
                ) VALUES (
                    :id, :name, :parent_id, :sort_order, :color
                )""",
                data,
            )
            self._db.commit()
            return

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if not vm.is_unlocked:
            raise RuntimeError("Cannot save group: Local Vault is locked.")
        vm.store_group(group)

        try:
            from services.sync_manager import SyncManager
            SyncManager.get().trigger_auto_sync()
        except Exception as se:
            logger.debug("Failed to trigger auto sync: %s", se)

    def list_groups(self) -> list[ConnectionGroup]:
        """List all connection groups."""
        if self._path != _default_db_path():
            rows = self._db.execute(
                "SELECT * FROM groups ORDER BY sort_order, name"
            ).fetchall()
            return [ConnectionGroup.from_dict(dict(r)) for r in rows]

        from services.vault_manager import VaultManager
        groups = VaultManager.get().list_groups()
        groups.sort(key=lambda g: (g.sort_order, g.name.lower()))
        return groups

    def delete_group(self, group_id: str) -> bool:
        """Remove a group. Connections in this group will have group_id set to NULL."""
        if self._path != _default_db_path():
            cur = self._db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            self._db.commit()
            return cur.rowcount > 0

        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if vm.is_unlocked:
            vm.delete_group(group_id)
            try:
                from services.sync_manager import SyncManager
                SyncManager.get().trigger_auto_sync()
            except Exception as se:
                logger.debug("Failed to trigger auto sync: %s", se)
            return True
        return False

    # ── Stats ─────────────────────────────────────────────────

    def count_connections(self) -> int:
        """Return the total number of saved connections."""
        if self._path != _default_db_path():
            row = self._db.execute("SELECT COUNT(*) FROM connections").fetchone()
            return row[0] if row else 0

        from services.vault_manager import VaultManager
        return len(VaultManager.get().list_connections())
