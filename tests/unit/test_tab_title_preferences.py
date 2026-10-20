# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for tab title preferences (alias vs metadata)."""

import sys
from unittest.mock import MagicMock, patch

# Mock GI and other GUI/network dependencies
class DummyBox:
    pass

gi_repo_mock = MagicMock()
gi_repo_mock.Gtk.Box = DummyBox
gi_repo_mock.Adw.Window = DummyBox

sys.modules["gi"] = MagicMock()
sys.modules["gi.repository"] = gi_repo_mock
sys.modules["asyncssh"] = MagicMock()

sys.path.insert(0, "src")

from db.database import Database
from models.connection import Connection
from views.terminal_view import TerminalTab, get_terminal_config
from views.sftp_view import SftpTab


def test_get_terminal_config_tab_title_style(tmp_path):
    db_path = str(tmp_path / "test_pref.db")
    db = Database(db_path)
    db.open()
    db.close()

    with patch("views.terminal_view.Database", side_effect=lambda: Database(db_path)):
        # Default should be metadata
        cfg = get_terminal_config(force_refresh=True)
        assert cfg["tab_title_style"] == "metadata"

        # Change to alias
        db.open()
        db.set_meta("tab_title_style", "alias")
        db.close()

        cfg = get_terminal_config(force_refresh=True)
        assert cfg["tab_title_style"] == "alias"

        # Invalid value should fallback to metadata
        db.open()
        db.set_meta("tab_title_style", "unknown_mode")
        db.close()

        cfg = get_terminal_config(force_refresh=True)
        assert cfg["tab_title_style"] == "metadata"


def test_terminal_tab_title_metadata_and_alias():
    conn = Connection(
        id="c1",
        name="Production Web",
        hostname="web.example.com",
        username="admin",
    )

    tab = object.__new__(TerminalTab)
    tab._connection = conn

    # 1. Metadata mode
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "metadata"}):
        assert tab.title == "admin@web.example.com"

    # 2. Alias mode with valid name
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "alias"}):
        assert tab.title == "Production Web"

    # 3. Alias mode with empty/whitespace name (should fallback to metadata)
    tab._connection = Connection(
        id="c2",
        name="   ",
        hostname="db.example.com",
        username="postgres",
    )
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "alias"}):
        assert tab.title == "postgres@db.example.com"

    # 4. Connection without username
    tab._connection = Connection(
        id="c3",
        name="",
        hostname="router.local",
        username="",
    )
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "metadata"}):
        assert tab.title == "router.local"

    # 5. Local shell (no connection)
    tab._connection = None
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "alias"}):
        assert tab.title == "Local Shell"


def test_sftp_tab_title_metadata_and_alias():
    conn = Connection(
        id="s1",
        name="Backup Server",
        hostname="backup.example.com",
        username="root",
    )

    tab = object.__new__(SftpTab)
    tab._conn = conn

    # 1. Metadata mode
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "metadata"}):
        assert tab.title == "SFTP — root@backup.example.com"

    # 2. Alias mode with valid name
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "alias"}):
        assert tab.title == "SFTP — Backup Server"

    # 3. Alias mode with empty name fallback
    conn.name = ""
    with patch("views.terminal_view.get_terminal_config", return_value={"tab_title_style": "alias"}):
        assert tab.title == "SFTP — root@backup.example.com"
