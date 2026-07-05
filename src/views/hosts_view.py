# SPDX-License-Identifier: GPL-3.0-or-later

"""Hosts Page — grid view of all connections."""

from __future__ import annotations

import logging
from typing import Any, Callable

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango

from db.database import Database, ValidationError
from models.connection import Connection, AuthMethod
from services.vault_manager import VaultManager
from utils.secure import SecureBytes

logger = logging.getLogger(__name__)
import gettext
_ = gettext.gettext

class DetailRow(Gtk.ListBoxRow):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.set_selectable(False)
        self.set_activatable(False)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        title_lbl = Gtk.Label(label=title)
        title_lbl.set_halign(Gtk.Align.START)
        title_lbl.add_css_class("heading")
        box.append(title_lbl)
        
        self.value_lbl = Gtk.Label()
        self.value_lbl.set_halign(Gtk.Align.START)
        self.value_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        self.value_lbl.set_max_width_chars(38)
        self.value_lbl.add_css_class("caption")
        self.value_lbl.add_css_class("dim-label")
        box.append(self.value_lbl)
        
        self.set_child(box)

    def set_subtitle(self, text: str) -> None:
        self.value_lbl.set_label(text)



class HostCard(Gtk.FlowBoxChild):
    """A card representing a connection in the Hosts grid."""

    # Maps auth method value -> CSS stripe class (top color band)
    _AUTH_STRIPE: dict[str, str] = {
        "key":            "auth-stripe-key",
        "password":       "auth-stripe-password",
        "key_passphrase": "auth-stripe-key_passphrase",
        "agent":          "auth-stripe-agent",
        "vault":          "auth-stripe-vault",
    }

    # Maps auth method value -> short badge text
    _AUTH_BADGE: dict[str, str] = {
        "key":            "SSH Key",
        "password":       "Password",
        "key_passphrase": "Key+Pass",
        "agent":          "Agent",
        "vault":          "Vault Key",
    }

    def __init__(self, connection: Connection) -> None:
        super().__init__()
        self.connection = connection
        self.set_size_request(210, -1)
        self.set_halign(Gtk.Align.START)
        self.set_margin_start(5)
        self.set_margin_end(5)
        self.set_margin_top(5)
        self.set_margin_bottom(5)
        self.add_css_class("host-card")

        auth_val = connection.auth_method.value

        # Outer container with new card styling
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.add_css_class("host-card-v2")
        outer.add_css_class(self._AUTH_STRIPE.get(auth_val, "auth-stripe-key"))
        outer.set_size_request(210, -1)
        outer.set_halign(Gtk.Align.FILL)

        # Card body
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        body.set_margin_start(12)
        body.set_margin_end(12)
        body.set_margin_top(10)
        body.set_margin_bottom(10)

        # Row 1: OS icon + connection name + auth badge (top-right)
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        row1.append(self._get_os_icon_widget(connection.os_id))

        name_lbl = Gtk.Label(label=connection.name)
        name_lbl.set_halign(Gtk.Align.START)
        name_lbl.set_hexpand(True)
        name_lbl.add_css_class("heading")
        name_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        row1.append(name_lbl)

        badge = Gtk.Label(label=self._AUTH_BADGE.get(auth_val, auth_val))
        badge.add_css_class("auth-badge")
        row1.append(badge)
        body.append(row1)

        # Row 2: host string
        host_str = (
            f"{connection.username}@{connection.hostname}"
            if connection.username
            else connection.hostname
        )
        if connection.port != 22:
            host_str += f":{connection.port}"

        host_lbl = Gtk.Label(label=host_str)
        host_lbl.set_halign(Gtk.Align.START)
        host_lbl.add_css_class("caption")
        host_lbl.add_css_class("dim-label")
        host_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        body.append(host_lbl)

        outer.append(body)
        self.set_child(outer)

    def _get_os_icon_widget(self, os_id: str | None) -> Gtk.Widget:
        """Helper to create an OS icon widget based on ID."""
        if not os_id:
            img = Gtk.Image.new_from_icon_name("network-server-symbolic")
            img.set_pixel_size(16)
            return img

        from pathlib import Path
        safe_os_id = "".join(c for c in os_id if c.isalnum() or c in "-_").lower()

        # Check standard search locations
        dev_icon_dir = Path(__file__).parent.parent.parent / "data" / "icons" / "os"
        installed_icon_dir = Path("/app/share/sentinel/icons/os")
        search_dirs = [dev_icon_dir, installed_icon_dir]

        for ext in ["-symbolic.svg", ".svg"]:
            filename = f"{safe_os_id}{ext}"
            for icon_dir in search_dirs:
                if not icon_dir.exists():
                    continue
                path = icon_dir / filename
                if path.exists():
                    icon_file = Gio.File.new_for_path(str(path))
                    gicon = Gio.FileIcon.new(icon_file)
                    img = Gtk.Image.new_from_gicon(gicon)
                    img.set_pixel_size(16)
                    return img

        img = Gtk.Image.new_from_icon_name("network-server-symbolic")
        img.set_pixel_size(16)
        return img


class HostsPage(Gtk.Box):
    """The Hosts page displaying connections in a grid with an Info Panel."""

    def __init__(
        self,
        parent_window: Any,
        connect_callback: Callable[[Connection], None],
        edit_callback: Callable[[Connection], None],
        sftp_callback: Callable[[Connection], None],
        delete_callback: Callable[[Connection, Gtk.Widget], None],
        clear_host_key_callback: Callable[[Connection], None],
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL)
        self._parent = parent_window
        self._connect_cb = connect_callback
        self._edit_cb = edit_callback
        self._sftp_cb = sftp_callback
        self._delete_cb = delete_callback
        self._clear_host_key_cb = clear_host_key_callback

        self._db = Database()
        self._connections: list[Connection] = []
        self._selected_conn: Connection | None = None
        self._editing_conn: Connection | None = None
        self._vault_sel_name_val: str = ""
        self._last_selected_card = None

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # Left Content Area (Toolbar + Grid Stack)
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        left_box.set_hexpand(True)

        # Actions/Toolbar Bar
        actions_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions_bar.set_margin_start(16)
        actions_bar.set_margin_end(16)
        actions_bar.set_margin_top(12)
        actions_bar.set_margin_bottom(12)

        # Search Entry
        self._search_entry = Gtk.SearchEntry(placeholder_text=_("Search hosts…"))
        self._search_entry.set_size_request(240, -1)
        self._search_entry.connect("search-changed", self._on_search_changed)
        actions_bar.append(self._search_entry)

        actions_spacer = Gtk.Box()
        actions_spacer.set_hexpand(True)
        actions_bar.append(actions_spacer)

        # + Add Host button
        add_host_btn = Gtk.Button(label=_("New Host"))
        add_host_btn.add_css_class("suggested-action")
        add_host_btn.connect("clicked", lambda _: self.show_editor(None))
        actions_bar.append(add_host_btn)

        left_box.append(actions_bar)

        # Scrolled Grid Window
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_margin_start(16)
        scroll.set_margin_end(16)
        scroll.set_margin_bottom(16)

        # Grid Stack for empty state vs grid
        self._left_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=200,
        )

        # Grid view (FlowBox)
        self._flow_box = Gtk.FlowBox()
        self._flow_box.set_valign(Gtk.Align.START)
        self._flow_box.set_max_children_per_line(10)
        self._flow_box.set_homogeneous(True)
        self._flow_box.set_min_children_per_line(1)
        self._flow_box.set_selection_mode(Gtk.SelectionMode.MULTIPLE)
        self._flow_box.connect("child-activated", self._on_card_activated)
        self._flow_box.connect("selected-children-changed", self._on_selection_changed)

        scroll.set_child(self._flow_box)
        self._left_stack.add_named(scroll, "grid")

        # Empty state
        empty_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            vexpand=True,
        )
        empty_icon = Gtk.Image.new_from_icon_name("network-server-symbolic")
        empty_icon.set_pixel_size(48)
        empty_icon.set_opacity(0.3)
        empty_box.append(empty_icon)

        empty_label = Gtk.Label(label=_("No Hosts Configured"))
        empty_label.add_css_class("title-2")
        empty_box.append(empty_label)

        empty_desc = Gtk.Label(label=_("Click 'New Host' to configure your first SSH host connection."))
        empty_desc.add_css_class("dim-label")
        empty_box.append(empty_desc)
        
        self._left_stack.add_named(empty_box, "empty")
        left_box.append(self._left_stack)

        self.append(left_box)

        # Separator
        self._sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        self.append(self._sep)

        # Right Panel (Host Info)
        self._right_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._right_panel.set_size_request(390, -1)
        self._right_panel.set_visible(True)

        # Clamp wrapper for right panel
        self._right_clamp = Adw.Clamp()
        self._right_clamp.set_maximum_size(390)
        self._right_clamp.set_child(self._right_panel)
        self._right_clamp.set_hexpand(False)
        self._right_clamp.set_halign(Gtk.Align.END)
        self._right_clamp.set_visible(False)

        # Editor Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        header_box.set_margin_start(16)
        header_box.set_margin_end(16)
        header_box.set_margin_top(12)
        header_box.set_margin_bottom(12)

        self._editor_title = Gtk.Label()
        self._editor_title.add_css_class("title-2")
        header_box.append(self._editor_title)

        header_spacer = Gtk.Box()
        header_spacer.set_hexpand(True)
        header_box.append(header_spacer)

        close_btn = Gtk.Button(icon_name="window-close-symbolic")
        close_btn.add_css_class("flat")
        close_btn.connect("clicked", lambda _: self._close_right_panel())
        header_box.append(close_btn)

        self._right_panel.append(header_box)

        # Editor Body
        self._build_editor_ui()
        self.append(self._right_clamp)

    def _build_editor_ui(self) -> None:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_margin_start(16)
        scroll.set_margin_end(16)
        scroll.set_margin_bottom(16)

        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # ─── Basic group ───
        basic_group = Adw.PreferencesGroup(title=_("Basic"))
        basic_group.add_css_class("editor-page")

        self._name_row = Adw.EntryRow(title=_("Name"))
        basic_group.add(self._name_row)

        self._host_row = Adw.EntryRow(title=_("Hostname"))
        basic_group.add(self._host_row)

        self._port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        self._port_row.set_title(_("Port"))
        port_focus_controller = Gtk.EventControllerFocus.new()
        port_focus_controller.connect("enter", lambda *_: GLib.idle_add(self._port_row.select_region, 0, -1))
        self._port_row.add_controller(port_focus_controller)
        basic_group.add(self._port_row)

        self._user_row = Adw.EntryRow(title=_("Username"))
        focus_controller = Gtk.EventControllerFocus.new()
        focus_controller.connect("enter", lambda *_: GLib.idle_add(self._user_row.select_region, 0, -1))
        self._user_row.add_controller(focus_controller)
        basic_group.add(self._user_row)

        form_box.append(basic_group)

        # ─── Auth group ───
        auth_group = Adw.PreferencesGroup(title=_("Authentication"))
        auth_group.add_css_class("editor-page")

        auth_items = Gtk.StringList.new(
            [_("SSH Key"), _("Password"), _("Key + Passphrase"), _("SSH Agent"), _("Vault")]
        )
        self._auth_row = Adw.ComboRow(title=_("Method"), model=auth_items)
        
        self._auth_map = {
            AuthMethod.KEY: 0,
            AuthMethod.PASSWORD: 1,
            AuthMethod.KEY_PASSPHRASE: 2,
            AuthMethod.AGENT: 3,
            AuthMethod.VAULT: 4,
        }
        self._reverse_auth_map = {v: k for k, v in self._auth_map.items()}
        auth_group.add(self._auth_row)

        # Key selection row
        key_list = Gtk.StringList.new([_("Local File Path"), _("Keychain")])
        self._key_sel_row = Adw.ComboRow(title=_("Key Source"), model=key_list)
        auth_group.add(self._key_sel_row)

        # Keychain key selection row
        keychain_key_list = Gtk.StringList.new([_("No keys stored")])
        self._keychain_key_row = Adw.ComboRow(title=_("Keychain Key"), model=keychain_key_list)
        auth_group.add(self._keychain_key_row)

        self._key_row = Adw.EntryRow(title=_("Key File Path (optional)"))
        auth_group.add(self._key_row)

        self._password_row = Adw.PasswordEntryRow(title=_("Password"))
        auth_group.add(self._password_row)

        # Vault selection (Vertical layout to prevent squeezing in narrow sidebar)
        self._vault_row = Adw.PreferencesRow()
        
        vault_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        vault_box.set_margin_start(16)
        vault_box.set_margin_end(16)
        vault_box.set_margin_top(10)
        vault_box.set_margin_bottom(10)

        vault_title_lbl = Gtk.Label(label=_("SSH Key from Vault"))
        vault_title_lbl.set_halign(Gtk.Align.START)
        vault_title_lbl.add_css_class("heading")
        vault_box.append(vault_title_lbl)

        vault_subtitle_lbl = Gtk.Label(label=_("Select vault item storing the private key"))
        vault_subtitle_lbl.set_halign(Gtk.Align.START)
        vault_subtitle_lbl.add_css_class("caption")
        vault_subtitle_lbl.add_css_class("dim-label")
        vault_subtitle_lbl.set_wrap(True)
        vault_subtitle_lbl.set_max_width_chars(38)
        vault_box.append(vault_subtitle_lbl)

        # Spacer
        spacer = Gtk.Box()
        spacer.set_size_request(-1, 4)
        vault_box.append(spacer)

        # Controls row (value label + clear/browse buttons)
        vault_control_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)

        self._vault_label = Gtk.Label()
        self._vault_label.set_halign(Gtk.Align.START)
        self._vault_label.set_hexpand(True)
        self._vault_label.set_ellipsize(Pango.EllipsizeMode.END)
        self._vault_label.add_css_class("caption")
        self._vault_label.add_css_class("dim-label")
        vault_control_box.append(self._vault_label)

        vault_clear_btn = Gtk.Button(icon_name="edit-clear-symbolic")
        vault_clear_btn.set_tooltip_text(_("Clear vault key selection"))
        vault_clear_btn.set_valign(Gtk.Align.CENTER)
        vault_clear_btn.add_css_class("flat")
        vault_clear_btn.add_css_class("circular")
        vault_clear_btn.connect("clicked", lambda _: self._update_vault_label(None))
        vault_control_box.append(vault_clear_btn)

        vault_browse_btn = Gtk.Button(label=_("Select…"))
        vault_browse_btn.set_tooltip_text(_("Select SSH key from Vault"))
        vault_browse_btn.set_valign(Gtk.Align.CENTER)
        vault_browse_btn.add_css_class("flat")
        vault_browse_btn.connect("clicked", self._on_browse_vault_clicked)
        vault_control_box.append(vault_browse_btn)

        vault_box.append(vault_control_box)
        self._vault_row.set_child(vault_box)
        auth_group.add(self._vault_row)

        self._auth_row.connect("notify::selected", self._on_auth_changed)
        self._key_sel_row.connect("notify::selected", self._on_auth_changed)

        form_box.append(auth_group)

        # ─── Notes group ───
        notes_group = Adw.PreferencesGroup(title=_("Notes"))
        notes_group.add_css_class("editor-page")
        self._notes_row = Adw.EntryRow(title=_("Notes"))
        notes_group.add(self._notes_row)
        form_box.append(notes_group)

        # Error label
        self._error_bar = Gtk.Label(label="")
        self._error_bar.add_css_class("error")
        self._error_bar.set_margin_start(12)
        self._error_bar.set_margin_end(12)
        self._error_bar.set_margin_top(8)
        self._error_bar.set_visible(False)
        form_box.append(self._error_bar)

        # Save Button
        self._save_btn = Gtk.Button(label=_("Save"))
        self._save_btn.add_css_class("suggested-action")
        self._save_btn.add_css_class("pill")
        self._save_btn.set_margin_top(16)
        self._save_btn.connect("clicked", self._on_save_clicked)
        form_box.append(self._save_btn)

        scroll.set_child(form_box)
        self._right_panel.append(scroll)

    def _on_auth_changed(self, *_args) -> None:
        method = self._reverse_auth_map.get(self._auth_row.get_selected(), AuthMethod.KEY)
        is_key_method = method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE)
        self._key_sel_row.set_visible(is_key_method)
        
        is_local_file = is_key_method and self._key_sel_row.get_selected() == 0
        is_keychain = is_key_method and self._key_sel_row.get_selected() == 1
        
        self._key_row.set_visible(is_local_file)
        self._keychain_key_row.set_visible(is_keychain)
        
        self._password_row.set_visible(method == AuthMethod.PASSWORD)
        self._vault_row.set_visible(method == AuthMethod.VAULT)

    def _update_vault_label(self, item_id: str | None, name: str = "") -> None:
        self._vault_sel_id_val = item_id
        self._vault_sel_name_val = name
        if item_id:
            display = name if name else (item_id[:18] + "…" if len(item_id) > 18 else item_id)
            self._vault_label.set_label(display)
        else:
            self._vault_label.set_label(_("Not selected"))

    def _on_browse_vault_clicked(self, _btn) -> None:
        """Open vault key picker — prompt for unlock if needed."""
        from services.vault_service import VaultService
        from gi.repository import GLib as _GLib
        from views.dialogs import prompt_vault_key_selection

        vault = VaultService.get().get_backend("bitwarden")
        if not vault or not vault.is_available:
            self._parent._show_toast(_("Bitwarden CLI not found. Install it first."))
            return

        def _on_picked(item_id: str | None, item_name: str) -> None:
            if item_id:
                self._update_vault_label(item_id, item_name)
            self._vault_picker = None

        picker = prompt_vault_key_selection(self._parent, None, _on_picked)
        self._vault_picker = picker

        async def _fetch_and_update():
            is_unlocked = await vault.is_unlocked()
            if not is_unlocked:
                def _notify_locked():
                    picker.destroy()
                    self._parent._show_toast(_("Please log in / unlock Bitwarden via Vault Settings first."))
                    self._parent.show_vault_settings()
                    return False
                _GLib.idle_add(_notify_locked)
                return

            try:
                items = await vault.search_credentials("", None)
                _GLib.idle_add(lambda: picker.set_items(items) and False)
            except Exception as fetch_err:
                def _on_error():
                    picker.destroy()
                    self._parent._show_toast(_("Failed to fetch vault items: {fetch_err}").format(fetch_err=fetch_err))
                    return False
                _GLib.idle_add(_on_error)

        from services.ssh_service import SSHService
        SSHService().engine.run_coroutine(_fetch_and_update())

    def show_editor(self, connection: Connection | None = None) -> None:
        """Show the editor panel for creating or editing a connection."""
        self._editing_conn = connection
        is_edit = connection is not None

        # Load keys from local Keychain
        vm = VaultManager.get()
        self._keychain_keys = []
        if vm.is_unlocked:
            try:
                self._keychain_keys = vm.list_global_keys()
            except Exception:
                pass

        # Build options for Keychain keys selection
        keychain_options = [k.get("label", "Unnamed Key") for k in self._keychain_keys]
        if not keychain_options:
            keychain_options = [_("No keys stored")]
        keychain_list = Gtk.StringList.new(keychain_options)
        self._keychain_key_row.set_model(keychain_list)

        self._error_bar.set_visible(False)

        if is_edit and connection:
            self._editor_title.set_label(_("Edit Connection"))
            self._name_row.set_text(connection.name)
            self._host_row.set_text(connection.hostname)
            self._port_row.set_value(connection.port)
            self._user_row.set_text(connection.username or "root")
            self._auth_row.set_selected(self._auth_map.get(connection.auth_method, 0))

            # Determine initial key selection
            key_source_sel = 0
            keychain_key_sel = 0
            if connection.key_path and connection.key_path.startswith("keychain:"):
                key_source_sel = 1
                target_id = connection.key_path.split(":", 1)[1]
                for idx, k in enumerate(self._keychain_keys):
                    if k.get("id") == target_id:
                        keychain_key_sel = idx
                        break
            self._key_sel_row.set_selected(key_source_sel)
            self._keychain_key_row.set_selected(keychain_key_sel)

            if connection.key_path and not connection.key_path.startswith("keychain:"):
                self._key_row.set_text(connection.key_path)
            else:
                self._key_row.set_text("")

            if connection.auth_method == AuthMethod.PASSWORD:
                pw = vm.get_cached_password(connection.id)
                if pw:
                    self._password_row.set_text(pw.unsafe_get_str())
                else:
                    self._password_row.set_text("")
            else:
                self._password_row.set_text("")

            self._update_vault_label(connection.vault_item_id, connection.vault_item_name or "")
            if connection.vault_item_id and not connection.vault_item_name:
                # Fallback: asynchronously fetch the name for legacy connections that don't have it saved
                def _fetch_vault_item_name(item_id):
                    import json
                    from services.vault_service import VaultService
                    from services.ssh_service import SSHService
                    from gi.repository import GLib

                    async def _async_fetch():
                        vault = VaultService.get().get_backend("bitwarden")
                        is_unlocked = await vault.is_unlocked() if vault else False
                        with open("/media/ailing/CS650/Docs/Sentinel/debug_vault.log", "a") as f:
                            f.write(f"Vault: {vault is not None}, Unlocked: {is_unlocked}, ItemID: {item_id}\n")
                        if vault and is_unlocked:
                            try:
                                item_raw = await vault._run_bw(["get", "item", item_id])
                                item = json.loads(item_raw)
                                name = item.get("name", "")
                                with open("/media/ailing/CS650/Docs/Sentinel/debug_vault.log", "a") as f:
                                    f.write(f"Success! Name: {name}\n")
                                if name:
                                    def _idle_update():
                                        if self._editing_conn and self._editing_conn.vault_item_id == item_id:
                                            self._update_vault_label(item_id, name)
                                            # Update connection model and save back so it is persisted
                                            self._editing_conn.vault_item_name = name
                                            try:
                                                self._db.open()
                                                self._db.save_connection(self._editing_conn)
                                                self._db.close()
                                            except Exception:
                                                pass
                                        return False
                                    GLib.idle_add(_idle_update)
                            except Exception as e:
                                with open("/media/ailing/CS650/Docs/Sentinel/debug_vault.log", "a") as f:
                                    f.write(f"Failed to fetch: {e}\n")
                                logger.error(f"Failed to fetch item name for {item_id}: {e}")

                    SSHService().engine.run_coroutine(_async_fetch())

                _fetch_vault_item_name(connection.vault_item_id)
            self._notes_row.set_text(connection.notes or "")
        else:
            self._editor_title.set_label(_("New Connection"))
            self._name_row.set_text("")
            self._host_row.set_text("")
            self._port_row.set_value(22)
            self._user_row.set_text("root")
            self._auth_row.set_selected(0)
            self._key_sel_row.set_selected(0)
            self._keychain_key_row.set_selected(0)
            self._key_row.set_text("")
            self._password_row.set_text("")
            self._update_vault_label(None)
            self._notes_row.set_text("")

        self._on_auth_changed()
        self._right_clamp.set_visible(True)
        self._sep.set_visible(True)

    def _on_save_clicked(self, _btn) -> None:
        is_edit = self._editing_conn is not None
        auth_method = self._reverse_auth_map.get(self._auth_row.get_selected(), AuthMethod.KEY)

        # Determine key path value
        k_path = None
        if auth_method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE):
            sel_idx = self._key_sel_row.get_selected()
            if sel_idx == 0:
                k_path = self._key_row.get_text() or None
            elif sel_idx == 1 and self._keychain_keys:
                kc_idx = self._keychain_key_row.get_selected()
                if 0 <= kc_idx < len(self._keychain_keys):
                    k_path = f"keychain:{self._keychain_keys[kc_idx]['id']}"

        if is_edit and self._editing_conn:
            conn = self._editing_conn
            conn.name = self._name_row.get_text()
            conn.hostname = self._host_row.get_text()
            conn.port = int(self._port_row.get_value())
            conn.username = self._user_row.get_text().strip() or "root"
            conn.auth_method = auth_method
            conn.key_path = k_path
            conn.vault_item_id = self._vault_sel_id_val
            conn.vault_item_name = self._vault_sel_name_val
            conn.notes = self._notes_row.get_text()
        else:
            conn = Connection(
                name=self._name_row.get_text(),
                hostname=self._host_row.get_text(),
                port=int(self._port_row.get_value()),
                username=self._user_row.get_text().strip() or "root",
                auth_method=auth_method,
                key_path=k_path,
                vault_item_id=self._vault_sel_id_val,
                vault_item_name=self._vault_sel_name_val,
                notes=self._notes_row.get_text(),
            )

        logger.info(f"on_save: saving connection: is_edit={is_edit}, id={conn.id}, name={conn.name}, host={conn.hostname}")
        try:
            self._db.open()
            try:
                self._db.save_connection(conn)
            finally:
                self._db.close()
        except ValidationError as e:
            logger.error(f"on_save validation error: {e}")
            self._error_bar.set_label(str(e))
            self._error_bar.set_visible(True)
            return

        # Password caches
        vm = VaultManager.get()
        if auth_method == AuthMethod.PASSWORD:
            password_text = self._password_row.get_text()
            if password_text:
                success = vm.cache_password(
                    item_id=conn.id,
                    label=f"Password for {conn.username}@{conn.hostname}",
                    password=SecureBytes(password_text),
                    hostname=conn.hostname,
                    username=conn.username
                )
                if not success:
                    self._parent._show_toast(_("Warning: Local Vault is locked. Password not saved."))
            else:
                vm.delete_cached_password(conn.id)
        else:
            vm.delete_cached_password(conn.id)

        self.refresh()
        self._close_right_panel()
        msg = _("Updated: {name}") if is_edit else _("Added: {name}")
        self._parent._show_toast(msg.format(name=conn.name))

    def _on_edit_toolbar_clicked(self) -> None:
        selected = self._flow_box.get_selected_children()
        if len(selected) == 1:
            self.show_editor(selected[0].connection)

    # ── Refresh & Handlers ────────────────────────────────────

    def refresh(self) -> None:
        """Reload connections from database and update grid."""
        self._last_selected_card = None
        # Check if the database needs to be queried
        self._db.open()
        try:
            self._connections = self._db.list_connections()
        except Exception as e:
            logger.error(f"HostsPage: Failed to list connections: {e}")
            self._connections = []
        finally:
            self._db.close()

        logger.info(f"HostsPage: refresh() retrieved {len(self._connections)} connections.")
        for c in self._connections:
            logger.info(f"  - Connection: name={c.name}, id={c.id}, host={c.hostname}")

        query = self._search_entry.get_text().strip().lower()
        if query:
            filtered = [
                c for c in self._connections
                if query in c.name.lower() or query in c.hostname.lower()
            ]
        else:
            filtered = self._connections

        # Clear FlowBox
        while True:
            child = self._flow_box.get_child_at_index(0)
            if child is None:
                break
            self._flow_box.remove(child)

        if not filtered:
            self._left_stack.set_visible_child_name("empty")
            self._close_right_panel()
            return

        for c in filtered:
            card = HostCard(c)
            self._flow_box.append(card)

            # Setup context menu gesture for right-click on cards
            self._setup_context_menu(card)
            # Setup left-click gesture for selection/activation
            self._setup_left_click(card)

        self._left_stack.set_visible_child_name("grid")

    def _setup_context_menu(self, card: HostCard) -> None:
        popover = Gtk.PopoverMenu()
        menu_model = Gio.Menu()
        menu_model.append(_("Connect"), "cardrow.connect")
        menu_model.append(_("SFTP"), "cardrow.sftp")
        menu_model.append(_("Copy Address"), "cardrow.copy")
        menu_model.append(_("Clear Host Key"), "cardrow.clear")
        menu_model.append(_("Edit"), "cardrow.edit")
        menu_model.append(_("Remove"), "cardrow.remove")
        popover.set_menu_model(menu_model)
        popover.set_parent(card)
        popover.set_has_arrow(False)
        popover.set_position(Gtk.PositionType.BOTTOM)

        action_group = Gio.SimpleActionGroup()
        
        conn = card.connection
        
        c_connect = Gio.SimpleAction.new("connect", None)
        c_connect.connect("activate", lambda *_: self._connect_cb(conn))
        action_group.add_action(c_connect)

        c_sftp = Gio.SimpleAction.new("sftp", None)
        c_sftp.connect("activate", lambda *_: self._sftp_cb(conn))
        action_group.add_action(c_sftp)

        c_copy = Gio.SimpleAction.new("copy", None)
        def _on_copy(*_):
            text = f"{conn.username}@{conn.hostname}" if conn.username else conn.hostname
            if conn.port != 22:
                text += f":{conn.port}"
            self.get_clipboard().set(text)
        c_copy.connect("activate", _on_copy)
        action_group.add_action(c_copy)

        c_clear = Gio.SimpleAction.new("clear", None)
        c_clear.connect("activate", lambda *_: self._clear_host_key_cb(conn))
        action_group.add_action(c_clear)

        c_edit = Gio.SimpleAction.new("edit", None)
        c_edit.connect("activate", lambda *_: self._edit_cb(conn))
        action_group.add_action(c_edit)

        c_remove = Gio.SimpleAction.new("remove", None)
        c_remove.connect("activate", lambda *_: self._delete_cb(conn, self._parent))
        action_group.add_action(c_remove)

        card.insert_action_group("cardrow", action_group)

        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)
        
        def _on_right_click(gesture_obj, n_press, x, y):
            if not card.is_selected():
                self._flow_box.unselect_all()
                self._flow_box.select_child(card)
                self._last_selected_card = card

            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            popover.set_pointing_to(rect)
            popover.popup()
            
        gesture.connect("pressed", _on_right_click)
        card.add_controller(gesture)

    def _on_card_activated(self, _flow_box: Gtk.FlowBox, card: HostCard) -> None:
        # Double-click or enter connects directly
        self._connect_cb(card.connection)

    def _setup_left_click(self, card: HostCard) -> None:
        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_PRIMARY)
        gesture.connect("pressed", self._on_card_left_clicked, card)
        card.add_controller(gesture)

    def _on_card_left_clicked(
        self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float, card: HostCard
    ) -> None:
        if n_press >= 2:
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
            self._connect_cb(card.connection)
            return

        if n_press == 1:
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
            card.grab_focus()

            event = gesture.get_current_event()
            state = event.get_modifier_state() if event else Gdk.ModifierType(0)
            is_ctrl = (state & Gdk.ModifierType.CONTROL_MASK) != 0
            is_shift = (state & Gdk.ModifierType.SHIFT_MASK) != 0

            if is_shift and self._last_selected_card is not None:
                all_cards = []
                child = self._flow_box.get_first_child()
                while child is not None:
                    if isinstance(child, HostCard):
                        all_cards.append(child)
                    child = child.get_next_sibling()

                try:
                    start_idx = all_cards.index(self._last_selected_card)
                    end_idx = all_cards.index(card)
                except ValueError:
                    start_idx = end_idx = 0

                low = min(start_idx, end_idx)
                high = max(start_idx, end_idx)

                self._flow_box.unselect_all()
                for i in range(low, high + 1):
                    self._flow_box.select_child(all_cards[i])
            elif is_ctrl:
                if card.is_selected():
                    self._flow_box.unselect_child(card)
                else:
                    self._flow_box.select_child(card)
                    self._last_selected_card = card
            else:
                self._flow_box.unselect_all()
                self._flow_box.select_child(card)
                self._last_selected_card = card

    def _on_selection_changed(self, _flow_box: Gtk.FlowBox) -> None:
        selected = self._flow_box.get_selected_children()

        # If the editor is open and selection changes, close it to avoid showing
        # stale or incorrect data.
        if self._right_clamp.get_visible():
            if len(selected) != 1 or selected[0].connection != self._editing_conn:
                self._right_clamp.set_visible(False)
                self._sep.set_visible(False)
                self._selected_conn = None
                self._editing_conn = None

    def _close_right_panel(self) -> None:
        self._right_clamp.set_visible(False)
        self._sep.set_visible(False)
        self._flow_box.unselect_all()
        self._selected_conn = None
        self._editing_conn = None

    def _on_search_changed(self, _entry: Gtk.SearchEntry) -> None:
        self.refresh()
