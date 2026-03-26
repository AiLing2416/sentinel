# SPDX-License-Identifier: GPL-3.0-or-later

"""Connection list sidebar widget."""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
import logging
from gi.repository import Adw, Gtk, Gdk, Gio  # noqa: E402

_ = gettext.gettext
logger = logging.getLogger(__name__)

from models.connection import Connection


class ConnectionListSidebar:
    """Manages the scrollable list of SSH connections in the sidebar."""

    def __init__(self) -> None:
        self._connections: list[Connection] = []
        self._selection_callback: Callable[[Connection | None], None] | None = None
        self._activated_callback: Callable[[Connection], None] | None = None
        self._sftp_callback: Callable[[Connection], None] | None = None
        self._edit_callback: Callable[[Connection], None] | None = None
        self._clear_host_key_callback: Callable[[Connection], None] | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, vexpand=True)

        # Scrolled window for the list
        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)

        self._list_box = Gtk.ListBox()
        self._list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list_box.add_css_class("navigation-sidebar")
        self._list_box.connect("row-selected", self._on_row_selected)
        self._list_box.connect("row-activated", self._on_row_activated)

        scroll.set_child(self._list_box)
        self._root.append(scroll)

        # Empty state
        self._empty_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=8,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            vexpand=True,
            margin_top=40,
            margin_bottom=40,
        )

        empty_icon = Gtk.Image.new_from_icon_name("network-server-symbolic")
        empty_icon.set_pixel_size(48)
        empty_icon.set_opacity(0.3)
        self._empty_box.append(empty_icon)
 
        empty_title = Gtk.Label(label=_("No Connections"))
        empty_title.add_css_class("empty-sidebar-title")
        self._empty_box.append(empty_title)

        empty_sub = Gtk.Label(label=_("Press + to add your first\nSSH connection"))
        empty_sub.add_css_class("empty-sidebar-subtitle")
        empty_sub.set_justify(Gtk.Justification.CENTER)
        self._empty_box.append(empty_sub)

        self._root.append(self._empty_box)

    @property
    def widget(self) -> Gtk.Widget:
        return self._root

    def connect_selection_changed(
        self, callback: Callable[[Connection | None], None]
    ) -> None:
        self._selection_callback = callback

    def connect_activated(
        self, callback: Callable[[Connection], None]
    ) -> None:
        """Register callback for row activation (connect shell)."""
        self._activated_callback = callback

    def connect_sftp_clicked(
        self, callback: Callable[[Connection], None]
    ) -> None:
        """Register callback for SFTP activation."""
        self._sftp_callback = callback

    def connect_edit_clicked(
        self, callback: Callable[[Connection], None]
    ) -> None:
        """Register callback for clicking the Edit button."""
        self._edit_callback = callback

    def connect_clear_host_key_clicked(
        self, callback: Callable[[Connection], None]
    ) -> None:
        """Register callback for clicking the Clear Host Key context menu item."""
        self._clear_host_key_callback = callback

    def set_connections(self, connections: list[Connection]) -> None:
        """Replace the list with new connection data."""
        self._connections = connections
        self._row_map: dict[str, Gtk.ListBoxRow] = {}

        # Remove existing rows
        while True:
            row = self._list_box.get_row_at_index(0)
            if row is None:
                break
            self._list_box.remove(row)

        # Show/hide empty state
        has_items = len(connections) > 0
        self._list_box.set_visible(has_items)
        self._empty_box.set_visible(not has_items)

        # Add rows
        for conn in connections:
            row = self._create_row(conn)
            self._row_map[conn.id] = row
            self._list_box.append(row)

    def refresh_os_icon(self, conn_id: str, os_id: str) -> None:
        """Update only the OS icon widget for a given connection row in place."""
        row = self._row_map.get(conn_id)
        if not row:
            logger.debug(f"Sidebar: Failed to refresh icon — connection {conn_id} not in row map")
            return
            
        logger.info(f"Sidebar: Refreshing OS icon for {conn_id} -> {os_id}")
            
        # Update the stored connection object so future re-renders are correct
        conn = getattr(row, "_connection", None)
        if conn:
            conn.os_id = os_id

        # The row child is the box, first child is the os_icon_box
        box = row.get_child()
        if not (box and isinstance(box, Gtk.Box)):
            logger.warning(f"Sidebar: Row child for {conn_id} is not a box")
            return
            
        os_icon_box = box.get_first_child()
        if not (os_icon_box and isinstance(os_icon_box, Gtk.Box)):
            logger.warning(f"Sidebar: Could not find os_icon_box for {conn_id}")
            return

        # Clear existing icon(s)
        while child := os_icon_box.get_first_child():
            os_icon_box.remove(child)
            
        # Create and append the new icon
        os_icon = self._get_os_icon_widget(os_id)
        os_icon_box.append(os_icon)
        logger.debug(f"Sidebar: OS icon updated for {conn_id}")

    def _get_os_icon_widget(self, os_id: str | None) -> Gtk.Widget:
        """Helper to create an OS icon widget based on ID."""
        if not os_id:
            return Gtk.Image.new_from_icon_name("network-server-symbolic")

        from pathlib import Path
        safe_os_id = "".join(c for c in os_id if c.isalnum() or c in "-_").lower()
        
        # Try finding the icon in our data folder
        icon_dir = Path(__file__).parent.parent.parent / "data" / "icons" / "os"
        
        # Check symbolic first, then regular
        for ext in ["-symbolic.svg", ".svg"]:
            path = icon_dir / f"{safe_os_id}{ext}"
            if path.exists():
                icon_file = Gio.File.new_for_path(str(path))
                gicon = Gio.FileIcon.new(icon_file)
                img = Gtk.Image.new_from_gicon(gicon)
                img.set_pixel_size(16)
                return img

        # Fallback to default
        return Gtk.Image.new_from_icon_name("network-server-symbolic")

    def _create_row(self, conn: Connection) -> Gtk.ListBoxRow:
        """Create a styled row for a connection."""
        row = Gtk.ListBoxRow()
        row.set_activatable(True)
        row._connection = conn  # type: ignore[attr-defined]

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.add_css_class("connection-row")

        # System/OS Icon
        os_icon_box = Gtk.Box(halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        os_icon_box.add_css_class("os-icon-box")
        os_icon_box.append(self._get_os_icon_widget(conn.os_id))
        box.append(os_icon_box)

        # Text (Name, Host, and Auth Badge)
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        text_box.set_hexpand(True)

        name_label = Gtk.Label(
            label=conn.name,
            xalign=0,
            ellipsize=3,  # PANGO_ELLIPSIZE_END
        )
        name_label.add_css_class("heading")
        text_box.append(name_label)

        host_str = f"{conn.username}@{conn.hostname}" if conn.username else conn.hostname
        if conn.port != 22:
            host_str += f":{conn.port}"
        host_label = Gtk.Label(label=host_str, xalign=0, ellipsize=3)
        host_label.add_css_class("host-label")
        text_box.append(host_label)

        box.append(text_box)

        # Right-aligned Auth Icon
        auth_icons = {
            "key": "changes-prevent-symbolic",
            "password": "dialog-password-symbolic",
            "key_passphrase": "channel-secure-symbolic",
            "agent": "system-users-symbolic",
            "vault": "security-high-symbolic",
        }
        auth_icon = Gtk.Image.new_from_icon_name(
            auth_icons.get(conn.auth_method.value, "dialog-password-symbolic")
        )
        auth_icon.set_opacity(0.4)
        auth_icon.set_valign(Gtk.Align.CENTER)
        box.append(auth_icon)

        row.set_child(box)

        # Context menu for right click
        popover = Gtk.PopoverMenu()
        menu_model = Gio.Menu()
        menu_model.append(_("Shell"), "row.connect_shell")
        menu_model.append(_("SFTP"), "row.connect_sftp")
        menu_model.append(_("Copy Host"), "row.copy_host")
        menu_model.append(_("Clear Host Key"), "row.clear_key")
        menu_model.append(_("Edit"), "row.edit")
        popover.set_menu_model(menu_model)
        popover.set_parent(row)
        popover.set_has_arrow(False)
        popover.set_position(Gtk.PositionType.BOTTOM)

        action_group = Gio.SimpleActionGroup()
        
        # Shell Action
        shell_action = Gio.SimpleAction.new("connect_shell", None)
        shell_action.connect("activate", lambda *_: self._on_row_activated(self._list_box, row))
        action_group.add_action(shell_action)

        # SFTP Action
        sftp_action = Gio.SimpleAction.new("connect_sftp", None)
        sftp_action.connect("activate", lambda *_: self._on_sftp_activated(row))
        action_group.add_action(sftp_action)
        
        # Copy Action
        copy_action = Gio.SimpleAction.new("copy_host", None)
        def _on_copy(*_args):
            text = f"{conn.username}@{conn.hostname}" if conn.username else conn.hostname
            if conn.port != 22:
                text += f":{conn.port}"
            row.get_clipboard().set(text)
        copy_action.connect("activate", _on_copy)
        action_group.add_action(copy_action)
        
        # Edit Action
        edit_action = Gio.SimpleAction.new("edit", None)
        def _on_edit(*_args):
            self._on_edit_clicked(conn)
        edit_action.connect("activate", _on_edit)
        action_group.add_action(edit_action)
        
        # Clear Host Key Action
        clear_key_action = Gio.SimpleAction.new("clear_key", None)
        def _on_clear_key(*_args):
            self._on_clear_host_key_clicked(conn)
        clear_key_action.connect("activate", _on_clear_key)
        action_group.add_action(clear_key_action)
        
        row.insert_action_group("row", action_group)

        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)
        
        def _on_right_click(gesture, n_press, x, y):
            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            popover.set_pointing_to(rect)
            popover.popup()
            
        gesture.connect("pressed", _on_right_click)
        row.add_controller(gesture)

        return row

    def _on_row_selected(self, _list_box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if self._selection_callback is None:
            return

        if row is None:
            self._selection_callback(None)
        else:
            conn = getattr(row, "_connection", None)
            self._selection_callback(conn)

    def _on_row_activated(self, _list_box: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        """Handle clicking on a row to connect."""
        if self._activated_callback is None:
            return
        conn = getattr(row, "_connection", None)
        if conn:
            self._activated_callback(conn)

    def _on_sftp_activated(self, row: Gtk.ListBoxRow) -> None:
        """Handle clicking on SFTP menu item."""
        if self._sftp_callback is None:
            return
        conn = getattr(row, "_connection", None)
        if conn:
            self._sftp_callback(conn)

    def _on_edit_clicked(self, conn: Connection) -> None:
        """Handle edit button click."""
        if self._edit_callback:
            self._edit_callback(conn)

    def _on_clear_host_key_clicked(self, conn: Connection) -> None:
        """Handle clear host key click."""
        if self._clear_host_key_callback:
            self._clear_host_key_callback(conn)
