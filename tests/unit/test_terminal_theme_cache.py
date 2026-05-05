import json
import os
import sys
from unittest.mock import MagicMock, patch

# Mock GI and other dependencies
sys.modules["gi"] = MagicMock()
sys.modules["gi.repository"] = MagicMock()
sys.modules["asyncssh"] = MagicMock()

sys.path.insert(0, "src")

import views.terminal_view
from views.terminal_view import get_terminal_theme
from db.database import Database

def test_theme_cache():
    db_path = "test_unit_theme.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db = Database(db_path)
    db.open()

    theme1 = {
        "id": "theme1",
        "name": "Theme 1",
        "background": "#111111",
        "foreground": "#eeeeee",
        "palette": ["#000000"] * 16
    }
    theme2 = {
        "id": "theme2",
        "name": "Theme 2",
        "background": "#222222",
        "foreground": "#dddddd",
        "palette": ["#000000"] * 16
    }

    db.set_meta("terminal_theme", json.dumps(theme1))
    db.close()

    with patch("views.terminal_view.Database") as MockDatabase:
        MockDatabase.side_effect = lambda: Database(db_path)

        # Initial load
        t = get_terminal_theme(force_refresh=True)
        assert t["id"] == "theme1"
        assert MockDatabase.called

        MockDatabase.reset_mock()

        # Subsequent load (should be cached)
        t = get_terminal_theme()
        assert t["id"] == "theme1"
        assert not MockDatabase.called

        # Update DB
        db.open()
        db.set_meta("terminal_theme", json.dumps(theme2))
        db.close()

        # Still cached
        t = get_terminal_theme()
        assert t["id"] == "theme1"

        # Force refresh
        t = get_terminal_theme(force_refresh=True)
        assert t["id"] == "theme2"
        assert MockDatabase.called

    if os.path.exists(db_path):
        os.remove(db_path)

if __name__ == "__main__":
    test_theme_cache()
    print("Test passed!")
