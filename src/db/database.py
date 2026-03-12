# SPDX-License-Identifier: GPL-3.0-or-later

"""SQLite database layer — connection configuration persistence.

Security note: This database intentionally stores NO passwords or private keys.
All sensitive credentials are delegated to the vault subsystem.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

from models.connection import Connection, ValidationError
from models.connection_group import ConnectionGroup

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────

_SCHEMA_VERSION = 1

_SCHEMA = """
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
    bind_address  TEXT DEFAULT '127.0.0.1',
    bind_port     INTEGER NOT NULL,
    remote_host   TEXT,
    remote_port   INTEGER,
    enabled       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS known_hosts (
    hostname    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    key_type    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    trusted     INTEGER DEFAULT 0,
    PRIMARY KEY (hostname, port, key_type)
);
"""


def _default_db_path() -> Path:
    """Return XDG-compliant database path."""
    data_dir = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    db_dir = Path(data_dir) / "sentinel"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "connections.db"


class Database:
    """Synchronous SQLite database for connection configuration.

    Thread-safety: Each Database instance owns one connection.
    Use separate instances for separate threads.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else _default_db_path()
        self._conn: sqlite3.Connection | None = None

    @property
    def path(self) -> Path:
        return self._path

    # ── Lifecycle ─────────────────────────────────────────────

    def open(self) -> None:
        """Open the database and ensure schema is applied."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._apply_schema()
        logger.info("Database opened: %s", self._path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.info("Database closed")

    def _apply_schema(self) -> None:
        """Create tables if they don't exist and run migrations."""
        assert self._conn is not None
        self._conn.executescript(_SCHEMA)

        # Set schema version if missing
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        if not row:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
            self._conn.commit()

        # Database Migration: add os_id if missing
        cols = [col["name"] for col in self._conn.execute("PRAGMA table_info(connections)").fetchall()]
        if "os_id" not in cols:
            self._conn.execute("ALTER TABLE connections ADD COLUMN os_id TEXT")
            self._conn.commit()

        if "agent_forwarding" not in cols:
            self._conn.execute("ALTER TABLE connections ADD COLUMN agent_forwarding INTEGER DEFAULT 0")
            self._conn.commit()

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not opened. Call open() first.")
        return self._conn

    # ── Meta / Settings ───────────────────────────────────────

    def set_meta(self, key: str, value: str) -> None:
        """Set a global app setting."""
        self._db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, value)
        )
        self._db.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        """Get a global app setting."""
        row = self._db.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

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

        data = conn.to_dict()
        cols = ", ".join(data.keys())
        placeholders = ", ".join(f":{k}" for k in data.keys())
        self._db.execute(
            f"INSERT OR REPLACE INTO connections ({cols}) VALUES ({placeholders})",
            data,
        )
        self._db.commit()
        logger.debug("Saved connection: %s (%s)", conn.name, conn.id)

    def get_connection(self, conn_id: str) -> Connection | None:
        """Retrieve a connection by ID."""
        row = self._db.execute(
            "SELECT * FROM connections WHERE id = ?", (conn_id,)
        ).fetchone()
        if row:
            return Connection.from_dict(dict(row))
        return None

    def list_connections(self, group_id: str | None = None) -> list[Connection]:
        """List all connections, optionally filtered by group."""
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

    def delete_connection(self, conn_id: str) -> bool:
        """Delete a connection by ID. Returns True if deleted."""
        cur = self._db.execute("DELETE FROM connections WHERE id = ?", (conn_id,))
        self._db.commit()
        deleted = cur.rowcount > 0
        if deleted:
            logger.debug("Deleted connection: %s", conn_id)
        return deleted

    def search_connections(self, query: str) -> list[Connection]:
        """Search connections by name or hostname (case-insensitive)."""
        pattern = f"%{query}%"
        rows = self._db.execute(
            "SELECT * FROM connections WHERE name LIKE ? OR hostname LIKE ? "
            "ORDER BY sort_order, name",
            (pattern, pattern),
        ).fetchall()
        return [Connection.from_dict(dict(r)) for r in rows]

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
            logger.debug(f"Cleared {cur.rowcount} host keys for {hostname}:{port}")
        return cur.rowcount

    # ── Group CRUD ────────────────────────────────────────────

    def save_group(self, group: ConnectionGroup) -> None:
        """Insert or replace a connection group."""
        group.validate()
        data = group.to_dict()
        cols = ", ".join(data.keys())
        placeholders = ", ".join(f":{k}" for k in data.keys())
        self._db.execute(
            f"INSERT OR REPLACE INTO groups ({cols}) VALUES ({placeholders})",
            data,
        )
        self._db.commit()

    def list_groups(self) -> list[ConnectionGroup]:
        """List all connection groups."""
        rows = self._db.execute(
            "SELECT * FROM groups ORDER BY sort_order, name"
        ).fetchall()
        return [ConnectionGroup.from_dict(dict(r)) for r in rows]

    def delete_group(self, group_id: str) -> bool:
        """Delete a group. Connections in this group will have group_id set to NULL."""
        cur = self._db.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        self._db.commit()
        return cur.rowcount > 0

    # ── Stats ─────────────────────────────────────────────────

    def count_connections(self) -> int:
        """Return the total number of saved connections."""
        row = self._db.execute("SELECT COUNT(*) FROM connections").fetchone()
        return row[0] if row else 0
