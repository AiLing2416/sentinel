# SPDX-License-Identifier: GPL-3.0-or-later

"""Preferences window for global appearance and basic terminal settings."""

from __future__ import annotations

import gettext
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402
from db.database import Database

_ = gettext.gettext

FONT_FAMILIES = [
    "Monospace",
    "DejaVu Sans Mono",
    "JetBrains Mono",
    "Cascadia Code",
    "Fira Code",
    "Ubuntu Mono",
]

CURSOR_SHAPES = [
    (_("Block (█)"), "block"),
    (_("I-Beam (❘)"), "ibeam"),
    (_("Underline (＿)"), "underline"),
]

CURSOR_BLINKS = [
    (_("System Default"), "system"),
    (_("Always On"), "on"),
    (_("Always Off"), "off"),
]

COLOR_SCHEMES = [
    (_("System Default"), "default"),
    (_("Light Mode"), "light"),
    (_("Dark Mode"), "dark"),
]


class PreferencesWindow(Adw.Window):
    """A standalone window for managing Application Preferences."""

    def __init__(self, app: Adw.Application) -> None:
        super().__init__(
            application=app,
            title=_("Preferences"),
            default_width=600,
            default_height=520,
        )

        self._db = Database()
        self._db.open()

        self._build_ui()
        self._load_preferences()

    def _build_ui(self) -> None:
        toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar_view.add_top_bar(header)

        page = Adw.PreferencesPage()

        # ── Group 1: Appearance ───────────────────────────────
        appearance_group = Adw.PreferencesGroup(title=_("Appearance"))

        # Global Color Scheme
        self._scheme_row = Adw.ComboRow(title=_("Color Scheme"))
        scheme_list = [item[0] for item in COLOR_SCHEMES]
        self._scheme_row.set_model(Gtk.StringList.new(scheme_list))
        self._scheme_handler = self._scheme_row.connect(
            "notify::selected", self._on_scheme_changed
        )
        appearance_group.add(self._scheme_row)
        page.add(appearance_group)

        # ── Group 2: Basic Terminal Settings ───────────────────
        term_group = Adw.PreferencesGroup(
            title=_("Basic Terminal Settings"),
            description=_("Configure font, cursor, and scrollback behavior for terminal tabs"),
        )

        # Font Family
        self._font_row = Adw.ComboRow(title=_("Font Family"))
        self._font_row.set_model(Gtk.StringList.new(FONT_FAMILIES))
        self._font_handler = self._font_row.connect(
            "notify::selected", self._on_font_changed
        )
        term_group.add(self._font_row)

        # Font Size
        self._font_size_row = Adw.SpinRow.new_with_range(6, 48, 1)
        self._font_size_row.set_title(_("Font Size"))
        self._font_size_handler = self._font_size_row.connect(
            "notify::value", self._on_font_size_changed
        )
        term_group.add(self._font_size_row)

        # Scrollback Lines
        self._scrollback_row = Adw.SpinRow.new_with_range(500, 100000, 500)
        self._scrollback_row.set_title(_("Scrollback Lines"))
        self._scrollback_row.set_subtitle(_("Number of history lines to retain in buffer"))
        self._scrollback_handler = self._scrollback_row.connect(
            "notify::value", self._on_scrollback_changed
        )
        term_group.add(self._scrollback_row)

        # Cursor Shape
        self._cursor_shape_row = Adw.ComboRow(title=_("Cursor Shape"))
        shape_list = [item[0] for item in CURSOR_SHAPES]
        self._cursor_shape_row.set_model(Gtk.StringList.new(shape_list))
        self._cursor_shape_handler = self._cursor_shape_row.connect(
            "notify::selected", self._on_cursor_shape_changed
        )
        term_group.add(self._cursor_shape_row)

        # Cursor Blink
        self._cursor_blink_row = Adw.ComboRow(title=_("Cursor Blink"))
        blink_list = [item[0] for item in CURSOR_BLINKS]
        self._cursor_blink_row.set_model(Gtk.StringList.new(blink_list))
        self._cursor_blink_handler = self._cursor_blink_row.connect(
            "notify::selected", self._on_cursor_blink_changed
        )
        term_group.add(self._cursor_blink_row)

        # OSC 52 Clipboard Integration
        self._osc52_row = Adw.SwitchRow(
            title=_("OSC 52 Clipboard Integration"),
            subtitle=_("Allow terminal programs (tmux, nvim) to set desktop clipboard"),
        )
        self._osc52_handler = self._osc52_row.connect(
            "notify::active", self._on_osc52_changed
        )
        term_group.add(self._osc52_row)

        # Terminal Hyperlinks (OSC 8)
        self._hyperlinks_row = Adw.SwitchRow(
            title=_("Terminal Hyperlinks (OSC 8)"),
            subtitle=_("Enable clickable links and URLs in terminal (Ctrl+Click to open)"),
        )
        self._hyperlinks_handler = self._hyperlinks_row.connect(
            "notify::active", self._on_hyperlinks_changed
        )
        term_group.add(self._hyperlinks_row)

        page.add(term_group)

        # Wrap in ScrolledWindow
        scroll = Gtk.ScrolledWindow()
        scroll.set_child(page)
        toolbar_view.set_content(scroll)

        self.set_content(toolbar_view)

    def _load_preferences(self) -> None:
        # Block signals while loading
        self._block_signals(True)

        # Load Color Scheme
        saved_scheme = self._db.get_meta("app_color_scheme", "default")
        scheme_idx = 0
        for i, (_, code) in enumerate(COLOR_SCHEMES):
            if code == saved_scheme:
                scheme_idx = i
                break
        self._scheme_row.set_selected(scheme_idx)

        # Load Font Family
        saved_font = self._db.get_meta("terminal_font_family", "Monospace")
        font_idx = 0
        for i, font_name in enumerate(FONT_FAMILIES):
            if font_name.lower() == saved_font.lower():
                font_idx = i
                break
        self._font_row.set_selected(font_idx)

        # Load Font Size
        saved_size = int(self._db.get_meta("terminal_font_size", "11"))
        self._font_size_row.set_value(saved_size)

        # Load Scrollback Lines
        saved_scrollback = int(self._db.get_meta("terminal_scrollback_lines", "10000"))
        self._scrollback_row.set_value(saved_scrollback)

        # Load Cursor Shape
        saved_shape = self._db.get_meta("terminal_cursor_shape", "block")
        shape_idx = 0
        for i, (_, code) in enumerate(CURSOR_SHAPES):
            if code == saved_shape:
                shape_idx = i
                break
        self._cursor_shape_row.set_selected(shape_idx)

        # Load Cursor Blink
        saved_blink = self._db.get_meta("terminal_cursor_blink", "system")
        blink_idx = 0
        for i, (_, code) in enumerate(CURSOR_BLINKS):
            if code == saved_blink:
                blink_idx = i
                break
        self._cursor_blink_row.set_selected(blink_idx)

        # Load OSC 52
        saved_osc52 = self._db.get_meta("terminal_enable_osc52", "true") == "true"
        self._osc52_row.set_active(saved_osc52)

        # Load Hyperlinks
        saved_hyperlinks = self._db.get_meta("terminal_enable_hyperlinks", "true") == "true"
        self._hyperlinks_row.set_active(saved_hyperlinks)

        self._block_signals(False)

    def _block_signals(self, block: bool) -> None:
        if block:
            self._scheme_row.handler_block(self._scheme_handler)
            self._font_row.handler_block(self._font_handler)
            self._font_size_row.handler_block(self._font_size_handler)
            self._scrollback_row.handler_block(self._scrollback_handler)
            self._cursor_shape_row.handler_block(self._cursor_shape_handler)
            self._cursor_blink_row.handler_block(self._cursor_blink_handler)
            self._osc52_row.handler_block(self._osc52_handler)
            self._hyperlinks_row.handler_block(self._hyperlinks_handler)
        else:
            self._scheme_row.handler_unblock(self._scheme_handler)
            self._font_row.handler_unblock(self._font_handler)
            self._font_size_row.handler_unblock(self._font_size_handler)
            self._scrollback_row.handler_unblock(self._scrollback_handler)
            self._cursor_shape_row.handler_unblock(self._cursor_shape_handler)
            self._cursor_blink_row.handler_unblock(self._cursor_blink_handler)
            self._osc52_row.handler_unblock(self._osc52_handler)
            self._hyperlinks_row.handler_unblock(self._hyperlinks_handler)

    def _on_scheme_changed(self, *args) -> None:
        idx = self._scheme_row.get_selected()
        if 0 <= idx < len(COLOR_SCHEMES):
            scheme_code = COLOR_SCHEMES[idx][1]
            self._db.set_meta("app_color_scheme", scheme_code)

            # Apply instantly
            style_mgr = Adw.StyleManager.get_default()
            if scheme_code == "light":
                style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)
            elif scheme_code == "dark":
                style_mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            else:
                style_mgr.set_color_scheme(Adw.ColorScheme.DEFAULT)

    def _on_font_changed(self, *args) -> None:
        idx = self._font_row.get_selected()
        if 0 <= idx < len(FONT_FAMILIES):
            font_name = FONT_FAMILIES[idx]
            self._db.set_meta("terminal_font_family", font_name)
            self._notify_terminal_config_changed()

    def _on_font_size_changed(self, *args) -> None:
        val = int(self._font_size_row.get_value())
        self._db.set_meta("terminal_font_size", str(val))
        self._notify_terminal_config_changed()

    def _on_scrollback_changed(self, *args) -> None:
        val = int(self._scrollback_row.get_value())
        self._db.set_meta("terminal_scrollback_lines", str(val))
        self._notify_terminal_config_changed()

    def _on_cursor_shape_changed(self, *args) -> None:
        idx = self._cursor_shape_row.get_selected()
        if 0 <= idx < len(CURSOR_SHAPES):
            shape_code = CURSOR_SHAPES[idx][1]
            self._db.set_meta("terminal_cursor_shape", shape_code)
            self._notify_terminal_config_changed()

    def _on_cursor_blink_changed(self, *args) -> None:
        idx = self._cursor_blink_row.get_selected()
        if 0 <= idx < len(CURSOR_BLINKS):
            blink_code = CURSOR_BLINKS[idx][1]
            self._db.set_meta("terminal_cursor_blink", blink_code)
            self._notify_terminal_config_changed()

    def _on_osc52_changed(self, *args) -> None:
        val = "true" if self._osc52_row.get_active() else "false"
        self._db.set_meta("terminal_enable_osc52", val)
        self._notify_terminal_config_changed()

    def _on_hyperlinks_changed(self, *args) -> None:
        val = "true" if self._hyperlinks_row.get_active() else "false"
        self._db.set_meta("terminal_enable_hyperlinks", val)
        self._notify_terminal_config_changed()

    def _notify_terminal_config_changed(self) -> None:
        app = self.get_application()
        if app:
            for win in app.get_windows():
                if hasattr(win, "refresh_terminal_config"):
                    win.refresh_terminal_config()

    def do_close_request(self) -> bool:
        self._db.close()
        return False
