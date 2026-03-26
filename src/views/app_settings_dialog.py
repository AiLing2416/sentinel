# SPDX-License-Identifier: GPL-3.0-or-later

"""Application settings dialog."""

from __future__ import annotations

import gettext
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402
from db.database import Database

_ = gettext.gettext


class AppSettingsWindow(Adw.Window):
    """A standalone window for managing Application settings."""

    def __init__(self, app: Adw.Application) -> None:
        super().__init__(
            application=app,
            title=_("App Settings"),
            default_width=500,
            default_height=300,
        )

        self._db = Database()
        self._db.open()

        self._build_ui()
        self._load_settings()

    def _build_ui(self) -> None:
        toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        # Settings Page
        page = Adw.PreferencesPage()

        # General Group
        general_group = Adw.PreferencesGroup(title=_("General"))

        # Language Dropdown
        self._language_row = Adw.ComboRow(title=_("Language"))
        self._language_row.set_subtitle(_("Requires an application restart to fully apply"))

        # Available languages mapping
        # Index corresponds to the position in the ComboRow
        self._languages = [
            ("Auto", ""),
            ("English", "en"),
            ("Simplified Chinese (简体中文)", "zh_CN"),
            ("Traditional Chinese (正体中文)", "zh_TW"),
            ("German (Deutsch)", "de")
        ]

        lang_list = [lang[0] for lang in self._languages]
        model = Gtk.StringList.new(lang_list)
        self._language_row.set_model(model)

        self._language_changed_handler = self._language_row.connect("notify::selected", self._on_language_changed)

        general_group.add(self._language_row)
        page.add(general_group)

        # Wrap in ScrolledWindow
        scroll = Gtk.ScrolledWindow()
        scroll.set_child(page)
        toolbar_view.set_content(scroll)

        self.set_content(toolbar_view)

    def _load_settings(self) -> None:
        lang_code = self._db.get_meta("app_language", "")
        self._current_lang_code = lang_code

        # Find index of language
        idx = 0
        for i, (_, code) in enumerate(self._languages):
            if code == lang_code:
                idx = i
                break

        # Block the signal while restoring the saved selection so that
        # _on_language_changed is not triggered during initialization.
        self._language_row.handler_block(self._language_changed_handler)
        self._language_row.set_selected(idx)
        self._language_row.handler_unblock(self._language_changed_handler)

    def _on_language_changed(self, *args) -> None:
        idx = self._language_row.get_selected()
        if 0 <= idx < len(self._languages):
            lang_code = self._languages[idx][1]

            # Skip if the selection didn't actually change
            if lang_code == self._current_lang_code:
                return

            self._current_lang_code = lang_code
            self._db.set_meta("app_language", lang_code)

            # Show a toast about restart
            # Get the main window toast overlay if possible
            app = self.get_application()
            if app:
                windows = app.get_windows()
                for w in windows:
                    if hasattr(w, "_show_toast"):
                        w._show_toast(_("Please restart the application for language changes to take effect."))
                        break

    def do_close_request(self) -> bool:
        self._db.close()
        return False
