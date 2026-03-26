# SPDX-License-Identifier: GPL-3.0-or-later

"""Terminal theme settings window."""

from __future__ import annotations

import json
import uuid
import gettext
from typing import Any, List, Optional

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, Gdk, Gio, GLib

from db.database import Database
from utils.themes import (
    PRESET_THEMES, 
    DEFAULT_THEME, 
    ThemeDict, 
    encode_theme, 
    decode_theme
)

_ = gettext.gettext

class TerminalThemeWindow(Adw.Window):
    """A window for managing terminal color themes with custom aliases and code sharing."""

    def __init__(self, app: Adw.Application) -> None:
        super().__init__(
            application=app,
            title=_("Terminal Theme"),
            default_width=640,
            default_height=560,
        )

        self._db = Database()
        self._db.open()
        
        # Data
        self._active_theme_id = self._db.get_meta("active_terminal_theme_id", DEFAULT_THEME["id"])
        self._custom_themes: List[ThemeDict] = self._load_custom_themes()
        self._current_theme: ThemeDict = self._load_active_theme()
        
        self._preset_handler_id = 0
        self._palette_buttons: List[tuple[Gtk.ColorDialogButton, int]] = []
        
        self._build_ui()
        self._update_preview()

    def _load_custom_themes(self) -> List[ThemeDict]:
        data = self._db.get_meta("custom_terminal_themes", "[]")
        try:
            return json.loads(data)
        except:
            return []

    def _save_custom_themes(self) -> None:
        self._db.set_meta("custom_terminal_themes", json.dumps(self._custom_themes))

    def _load_active_theme(self) -> ThemeDict:
        # Check presets
        for t in PRESET_THEMES:
            if t["id"] == self._active_theme_id:
                return t.copy()
        
        # Check custom
        for t in self._custom_themes:
            if t["id"] == self._active_theme_id:
                return t.copy()
        
        return DEFAULT_THEME.copy()

    def _save_active_theme_state(self) -> None:
        """Save the temporary edits of the active theme and notify app."""
        # Note: Presets can't be modified permanently, 
        # but the active selection state is stored in 'terminal_theme' for current session use.
        self._db.set_meta("terminal_theme", json.dumps(self._current_theme))
        self._db.set_meta("active_terminal_theme_id", self._current_theme["id"])
        
        # If it's a custom theme, also update it in the list
        for i, t in enumerate(self._custom_themes):
            if t["id"] == self._current_theme["id"]:
                self._custom_themes[i] = self._current_theme.copy()
                self._save_custom_themes()
                break

        # Notify application
        app = self.get_application()
        if app:
            for win in app.get_windows():
                if hasattr(win, "refresh_terminal_themes"):
                    win.refresh_terminal_themes()

    def _build_ui(self) -> None:
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        
        toolbar_view = Adw.ToolbarView()
        header = Adw.HeaderBar()
        
        # Add a "New" button to the header
        new_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=_("New Custom Theme"))
        new_btn.connect("clicked", lambda _: self._on_new_theme())
        header.pack_start(new_btn)
        
        toolbar_view.add_top_bar(header)

        # Content
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Preview area
        preview_frame = Gtk.Frame()
        preview_frame.set_margin_start(12)
        preview_frame.set_margin_end(12)
        preview_frame.set_margin_top(12)
        preview_frame.add_css_class("card")
        
        self._preview_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self._preview_box.set_margin_start(12)
        self._preview_box.set_margin_end(12)
        self._preview_box.set_margin_top(12)
        self._preview_box.set_margin_bottom(12)
        self._preview_box.set_size_request(-1, 100)
        
        self._preview_text_label = Gtk.Label(label=_("The quick brown fox jumps over the lazy dog"))
        self._preview_box.append(self._preview_text_label)
        
        self._palette_preview = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4, halign=Gtk.Align.CENTER)
        for i in range(16):
            dot = Gtk.Box()
            dot.set_size_request(20, 20)
            dot.add_css_class("palette-dot")
            self._palette_preview.append(dot)
        self._preview_box.append(self._palette_preview)
        
        preview_frame.set_child(self._preview_box)
        box.append(preview_frame)

        # Settings
        page = Adw.PreferencesPage()
        
        # ── Group: Theme Management ──
        mgmt_group = Adw.PreferencesGroup(title=_("Theme Management"))
        
        self._theme_row = Adw.ComboRow(title=_("Select Theme"))
        self._update_theme_model()
        self._preset_handler_id = self._theme_row.connect("notify::selected", self._on_theme_selection_changed)
        mgmt_group.add(self._theme_row)
        
        # Theme specific actions (Rename, Delete, Share)
        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6, halign=Gtk.Align.END)
        actions_box.set_margin_top(6)
        
        self._rename_btn = Gtk.Button(icon_name="edit-symbolic")
        self._rename_btn.set_tooltip_text(_("Rename Theme"))
        self._rename_btn.add_css_class("flat")
        self._rename_btn.connect("clicked", lambda _: self._on_rename_theme())
        
        self._delete_btn = Gtk.Button(icon_name="user-trash-symbolic")
        self._delete_btn.set_tooltip_text(_("Delete Theme"))
        self._delete_btn.add_css_class("flat")
        self._delete_btn.add_css_class("destructive-action")
        self._delete_btn.connect("clicked", lambda _: self._on_delete_theme())
        
        self._export_btn = Gtk.Button(label=_("Copy Code"), icon_name="edit-copy-symbolic")
        self._export_btn.set_tooltip_text(_("Copy sharing code to clipboard"))
        self._export_btn.add_css_class("flat")
        self._export_btn.connect("clicked", lambda _: self._on_export_code())
        
        actions_box.append(self._rename_btn)
        actions_box.append(self._delete_btn)
        actions_box.append(self._export_btn)
        
        # Add actions row
        self._mgmt_actions_row = Adw.ActionRow(title=_("Active Theme Settings"), 
                                              subtitle=_("Rename or delete your custom theme"))
        self._mgmt_actions_row.add_suffix(actions_box)
        mgmt_group.add(self._mgmt_actions_row)
        
        # Import Row
        import_row = Adw.ActionRow(title=_("Import from Code"), subtitle=_("Paste a theme code to import"))
        import_btn = Gtk.Button(label=_("Import..."))
        import_btn.set_valign(Gtk.Align.CENTER)
        import_btn.connect("clicked", lambda _: self._on_import_code())
        import_row.add_suffix(import_btn)
        mgmt_group.add(import_row)
        
        page.add(mgmt_group)

        # ── Group: Customization ──
        custom_group = Adw.PreferencesGroup(title=_("Customization"))
        self._fg_row = self._create_color_row(_("Foreground"), "foreground")
        self._bg_row = self._create_color_row(_("Background"), "background")
        self._cursor_row = self._create_color_row(_("Cursor"), "cursor")
        self._highlight_bg_row = self._create_color_row(_("Selection Background"), "highlight_bg")
        
        custom_group.add(self._fg_row)
        custom_group.add(self._bg_row)
        custom_group.add(self._cursor_row)
        custom_group.add(self._highlight_bg_row)
        
        # Palette Expander
        palette_expander = Adw.ExpanderRow(title=_("ANSI Colors Palette"))
        palette_grid = Gtk.Grid()
        palette_grid.set_column_spacing(12)
        palette_grid.set_row_spacing(12)
        palette_grid.set_margin_start(12)
        palette_grid.set_margin_end(12)
        palette_grid.set_margin_top(12)
        palette_grid.set_margin_bottom(12)
        
        self._palette_buttons = []
        for i in range(16):
            btn = Gtk.ColorDialogButton()
            btn.set_dialog(Gtk.ColorDialog())
            rgba = Gdk.RGBA()
            rgba.parse(self._current_theme["palette"][i])
            btn.set_rgba(rgba)
            h_id = btn.connect("notify::rgba", self._on_palette_color_changed, i)
            
            palette_grid.attach(btn, i % 8, i // 8, 1, 1)
            self._palette_buttons.append((btn, h_id))
        
        palette_expander.add_row(palette_grid)
        custom_group.add(palette_expander)
        page.add(custom_group)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(page)
        box.append(scroll)
        
        toolbar_view.set_content(box)
        
        # Add a toast overlay
        self._toast_overlay = Adw.ToastOverlay()
        self._toast_overlay.set_child(toolbar_view)
        main_box.append(self._toast_overlay)
        self.set_content(main_box)
        
        self._update_action_states()

    def _update_theme_model(self) -> None:
        all_themes = PRESET_THEMES + self._custom_themes
        names = [t["name"] for t in all_themes]
        
        if self._preset_handler_id:
            self._theme_row.handler_block(self._preset_handler_id)

        model = Gtk.StringList.new(names)
        self._theme_row.set_model(model)
        
        # Find index based on current theme ID
        idx = 0
        for i, t in enumerate(all_themes):
            if t["id"] == self._current_theme["id"]:
                idx = i
                break
        
        self._active_theme_id = all_themes[idx]["id"]
        self._theme_row.set_selected(idx)
        
        if self._preset_handler_id:
            self._theme_row.handler_unblock(self._preset_handler_id)

    def _update_action_states(self) -> None:
        is_custom = not self._current_theme.get("is_preset", False)
        self._rename_btn.set_sensitive(is_custom)
        self._delete_btn.set_sensitive(is_custom)

    def _create_color_row(self, title: str, key: str) -> Adw.ActionRow:
        row = Adw.ActionRow(title=title)
        btn = Gtk.ColorDialogButton()
        btn.set_dialog(Gtk.ColorDialog())
        rgba = Gdk.RGBA()
        rgba.parse(self._current_theme[key]) # type: ignore
        btn.set_rgba(rgba)
        btn.set_valign(Gtk.Align.CENTER)
        h_id = btn.connect("notify::rgba", self._on_basic_color_changed, key)
        row.add_suffix(btn)
        row._color_btn = btn # type: ignore
        row._color_handler_id = h_id # type: ignore
        return row

    # ── Theme Lifecycle ──

    def _on_theme_selection_changed(self, combo: Adw.ComboRow, _pspec: Any) -> None:
        idx = combo.get_selected()
        all_themes = PRESET_THEMES + self._custom_themes
        if 0 <= idx < len(all_themes):
            new_theme = all_themes[idx].copy()
            self._active_theme_id = new_theme["id"]
            self._current_theme = new_theme
            self._update_ui_from_theme()
            self._update_preview()
            self._save_active_theme_state()
            self._update_action_states()

    def _on_new_theme(self) -> None:
        # Create a copy of current theme as a new custom theme
        new_id = str(uuid.uuid4())
        new_theme = self._current_theme.copy()
        new_theme["id"] = new_id
        new_theme["name"] = f"{new_theme['name']} (Copy)"
        new_theme["is_preset"] = False
        
        self._custom_themes.append(new_theme)
        self._save_custom_themes()
        
        self._active_theme_id = new_id
        self._current_theme = new_theme
        self._update_theme_model()
        self._update_preview()
        self._save_active_theme_state()
        self._update_action_states()

    def _on_rename_theme(self) -> None:
        entry = Gtk.Entry(text=self._current_theme["name"])
        entry.set_margin_top(12)
        entry.set_margin_bottom(12)
        entry.set_margin_start(12)
        entry.set_margin_end(12)

        dialog = Adw.MessageDialog(
            heading=_("Rename Theme"),
            body=_("Enter a new name for this theme"),
        )
        dialog.set_transient_for(self)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("apply", _("Apply"))
        dialog.set_default_response("apply")
        dialog.set_close_response("cancel")
        
        entry.connect("activate", lambda _: dialog.response("apply"))
        
        def _on_response(d, response):
            if response == "apply":
                new_name = entry.get_text().strip()
                if new_name:
                    self._current_theme["name"] = new_name
                    for i, t in enumerate(self._custom_themes):
                        if t["id"] == self._current_theme["id"]:
                            self._custom_themes[i]["name"] = new_name
                            break
                    self._save_custom_themes()
                    self._update_theme_model()
                    self._save_active_theme_state()
        
        def _on_focus_grabbed():
            entry.grab_focus()
            # Select all text on open (standard rename behavior)
            entry.select_region(0, -1)
            return False

        dialog.connect("response", _on_response)
        dialog.present()
        GLib.idle_add(_on_focus_grabbed)

    def _on_delete_theme(self) -> None:
        dialog = Adw.AlertDialog(
            heading=_("Delete Theme?"),
            body=_("Are you sure you want to delete '{name}'?").format(name=self._current_theme["name"])
        )
        dialog.set_transient_for(self)
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("delete", _("Delete"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        
        def _on_response(d, response):
            if response == "delete":
                # Remove from custom list
                idx_to_remove = -1
                for i, t in enumerate(self._custom_themes):
                    if t["id"] == self._current_theme["id"]:
                        idx_to_remove = i
                        break
                if idx_to_remove != -1:
                    self._custom_themes.pop(idx_to_remove)
                    self._save_custom_themes()
                
                # Switch to default
                self._active_theme_id = DEFAULT_THEME["id"]
                self._current_theme = DEFAULT_THEME.copy()
                self._update_theme_model()
                self._update_ui_from_theme()
                self._update_preview()
                self._save_active_theme_state()
                self._update_action_states()

        dialog.connect("response", _on_response)
        dialog.present()

    # ── Color Change Handlers ──

    def _on_basic_color_changed(self, btn: Gtk.ColorDialogButton, _pspec: Any, key: str) -> None:
        self._current_theme[key] = btn.get_rgba().to_string() # type: ignore
        self._update_preview()
        self._save_active_theme_state()

    def _on_palette_color_changed(self, btn: Gtk.ColorDialogButton, _pspec: Any, index: int) -> None:
        self._current_theme["palette"][index] = btn.get_rgba().to_string()
        self._update_preview()
        self._save_active_theme_state()

    def _update_ui_from_theme(self) -> None:
        for row, key in [(self._fg_row, "foreground"), (self._bg_row, "background"), 
                         (self._cursor_row, "cursor"), (self._highlight_bg_row, "highlight_bg")]:
            rgba = Gdk.RGBA()
            rgba.parse(self._current_theme[key]) # type: ignore
            row._color_btn.handler_block(row._color_handler_id) # type: ignore
            row._color_btn.set_rgba(rgba) # type: ignore
            row._color_btn.handler_unblock(row._color_handler_id) # type: ignore
            
        for btn, h_id in self._palette_buttons:
            i = self._palette_buttons.index((btn, h_id))
            rgba = Gdk.RGBA()
            rgba.parse(self._current_theme["palette"][i])
            btn.handler_block(h_id)
            btn.set_rgba(rgba)
            btn.handler_unblock(h_id)

    def _update_preview(self) -> None:
        css = f"""
        .theme-preview {{ background-color: {self._current_theme["background"]}; border-radius: 8px; }}
        .palette-dot {{ border-radius: 10px; border: 1px solid alpha(gray, 0.3); }}
        label.theme-preview-text {{ color: {self._current_theme["foreground"]}; }}
        """
        provider = Gtk.CssProvider()
        provider.load_from_string(css)
        self._preview_box.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self._preview_box.add_css_class("theme-preview")
        
        text_provider = Gtk.CssProvider()
        text_provider.load_from_string(f"label {{ color: {self._current_theme['foreground']}; }}")
        self._preview_text_label.get_style_context().add_provider(text_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        
        dots = []
        c = self._palette_preview.get_first_child()
        while c:
            dots.append(c)
            c = c.get_next_sibling()
        for i, dot in enumerate(dots):
            d_css = f".palette-dot-{i} {{ background-color: {self._current_theme['palette'][i]}; }}"
            d_p = Gtk.CssProvider()
            d_p.load_from_string(d_css)
            dot.get_style_context().add_provider(d_p, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            dot.set_css_classes(["palette-dot", f"palette-dot-{i}"])

    # ── Sharing ──

    def _on_export_code(self) -> None:
        code = encode_theme(self._current_theme)
        clipboard = self.get_display().get_clipboard()
        clipboard.set(code)
        
        toast = Adw.Toast(title=_("Theme code copied to clipboard"))
        self._toast_overlay.add_toast(toast)

    def _on_import_code(self) -> None:
        entry = Gtk.Entry(placeholder_text=_("Paste code here..."))
        entry.set_margin_top(12)
        entry.set_margin_bottom(12)
        entry.set_margin_start(12)
        entry.set_margin_end(12)

        dialog = Adw.MessageDialog(
            heading=_("Import Theme"),
            body=_("Paste the theme code below:"),
        )
        dialog.set_transient_for(self)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("import", _("Import"))
        dialog.set_default_response("import")
        
        entry.connect("activate", lambda _: dialog.response("import"))
        
        def _on_response(d, response):
            if response == "import":
                code = entry.get_text().strip()
                new_theme = decode_theme(code, name=_("Imported Theme"))
                if new_theme:
                    self._custom_themes.append(new_theme)
                    self._save_custom_themes()
                    self._active_theme_id = new_theme["id"]
                    self._current_theme = new_theme
                    self._update_theme_model()
                    self._update_ui_from_theme()
                    self._update_preview()
                    self._save_active_theme_state()
                    self._update_action_states()
        
        def _on_focus_grabbed():
            entry.grab_focus()
            return False

        dialog.connect("response", _on_response)
        dialog.present()
        GLib.idle_add(_on_focus_grabbed)

    def do_close_request(self) -> bool:
        self._db.close()
        return False
