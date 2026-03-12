# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared test fixtures for Sentinel."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure src/ is importable
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from db.database import Database
from models.connection import AuthMethod, Connection


@pytest.fixture
def tmp_db(tmp_path: Path) -> Database:
    """Provide a fresh in-memory-like database for each test."""
    db_path = tmp_path / "test.db"
    db = Database(path=db_path)
    db.open()
    yield db
    db.close()


@pytest.fixture
def sample_connection() -> Connection:
    """A valid sample connection for testing."""
    return Connection(
        name="My Server",
        hostname="192.168.1.100",
        port=22,
        username="admin",
        auth_method=AuthMethod.KEY,
        key_path="~/.ssh/id_ed25519",
        notes="Test server",
    )


@pytest.fixture
def sample_connections() -> list[Connection]:
    """A list of valid sample connections for testing."""
    return [
        Connection(
            name="Production Web",
            hostname="web.example.com",
            port=22,
            username="deploy",
            auth_method=AuthMethod.KEY,
        ),
        Connection(
            name="Staging DB",
            hostname="10.0.1.50",
            port=2222,
            username="dbadmin",
            auth_method=AuthMethod.PASSWORD,
        ),
        Connection(
            name="Dev Box",
            hostname="dev.internal.local",
            port=22,
            username="developer",
            auth_method=AuthMethod.AGENT,
        ),
    ]
