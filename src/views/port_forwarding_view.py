# SPDX-License-Identifier: GPL-3.0-or-later

"""Port forwarding management tab view."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import os
import logging
from typing import Callable, Any
from gi.repository import Adw, Gtk, Gio, GLib

from db.database import Database
from models.forward_rule import ForwardRule, ForwardType
from models.connection import Connection, ValidationError
from services.ssh_service import SSHService

logger = logging.getLogger(__name__)
import gettext
_ = gettext.gettext


class PortForwardingDialog:
    """Dialog to create or edit a port forwarding rule."""

    def __init__(
        self,
        parent: Gtk.Widget,
        ssh_service: SSHService,
        rule: ForwardRule | None = None,
        callback: Callable[[ForwardRule | None], None] | None = None,
    ) -> None:
        self._ssh_service = ssh_service
        self._rule = rule
        self._callback = callback
        self._is_edit = rule is not None

        # Fetch all connections from database
        self._db = Database()
        self._db.open()
        try:
            self._connections = self._db.list_connections()
        finally:
            self._db.close()

        self._dialog = Adw.Dialog()
        self._dialog.set_title(_("Edit Port Forwarding") if self._is_edit else _("New Port Forwarding"))
        self._dialog.set_content_width(450)
        self._dialog.set_content_height(480)

        # UI Layout
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        toolbar.add_top_bar(header)

        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda _: self._dialog.close())
        header.pack_start(cancel_btn)

        self._save_btn = Gtk.Button(label=_("Save"))
        self._save_btn.add_css_class("suggested-action")
        self._save_btn.connect("clicked", self._on_save)
        header.pack_end(self._save_btn)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # Form fields Group
        group = Adw.PreferencesGroup()
        group.add_css_class("editor-page")

        # 1. Connection selection
        conn_names = [c.name for c in self._connections]
        if not conn_names:
            conn_names = [_("No SSH connections available")]
        string_list = Gtk.StringList.new(conn_names)
        self._conn_row = Adw.ComboRow(title=_("SSH Connection"), model=string_list)
        if self._is_edit and self._rule:
            for idx, c in enumerate(self._connections):
                if c.id == self._rule.connection_id:
                    self._conn_row.set_selected(idx)
                    break
        group.add(self._conn_row)

        # 2. Forwarding Type selection
        type_options = [_("Local Forwarding (-L)"), _("Remote Forwarding (-R)"), _("Dynamic Forwarding (-D SOCKS5)")]
        type_list = Gtk.StringList.new(type_options)
        self._type_row = Adw.ComboRow(title=_("Forward Type"), model=type_list)
        type_map = {
            ForwardType.LOCAL: 0,
            ForwardType.REMOTE: 1,
            ForwardType.DYNAMIC: 2,
        }
        self._reverse_type_map = {v: k for k, v in type_map.items()}
        if self._is_edit and self._rule:
            self._type_row.set_selected(type_map.get(self._rule.type, 0))
        group.add(self._type_row)

        # 3. Bind Address
        self._bind_addr_row = Adw.EntryRow(title=_("Bind Address (Default: localhost)"))
        self._bind_addr_row.set_text(self._rule.bind_address if (self._is_edit and self._rule) else "localhost")
        group.add(self._bind_addr_row)

        # 4. Bind Port
        self._bind_port_row = Adw.EntryRow(title=_("Bind Port"))
        if self._is_edit and self._rule:
            self._bind_port_row.set_text(str(self._rule.bind_port))
        group.add(self._bind_port_row)

        # 5. Remote Host
        self._remote_host_row = Adw.EntryRow(title=_("Remote Host"))
        self._remote_host_row.set_text(
            self._rule.remote_host if (self._is_edit and self._rule and self._rule.remote_host) else "localhost"
        )
        group.add(self._remote_host_row)

        # 6. Remote Port
        self._remote_port_row = Adw.EntryRow(title=_("Remote Port"))
        if self._is_edit and self._rule and self._rule.remote_port is not None:
            self._remote_port_row.set_text(str(self._rule.remote_port))
        group.add(self._remote_port_row)

        # 7. Auto Start
        self._autostart_row = Adw.SwitchRow(title=_("Automatically connect on app launch"))
        self._autostart_row.set_active(self._rule.auto_start if (self._is_edit and self._rule) else False)
        group.add(self._autostart_row)

        form_box.append(group)

        # Error label
        self._error_bar = Gtk.Label(label="")
        self._error_bar.add_css_class("error")
        self._error_bar.set_margin_start(12)
        self._error_bar.set_margin_end(12)
        self._error_bar.set_margin_top(8)
        self._error_bar.set_visible(False)
        form_box.append(self._error_bar)

        scroll.set_child(form_box)
        toolbar.set_content(scroll)
        self._dialog.set_child(toolbar)

        # Setup dynamic visibility based on Type selection
        self._type_row.connect("notify::selected", self._on_type_changed)
        self._on_type_changed()

        # Connect activate on entry fields to save
        for row in (self._bind_addr_row, self._bind_port_row, self._remote_host_row, self._remote_port_row):
            row.connect("entry-activated", lambda _: self._on_save(None))

        self._dialog.present(parent)

    def _on_type_changed(self, *args) -> None:
        selected_idx = self._type_row.get_selected()
        rule_type = self._reverse_type_map.get(selected_idx, ForwardType.LOCAL)
        show_remote = (rule_type != ForwardType.DYNAMIC)
        self._remote_host_row.set_visible(show_remote)
        self._remote_port_row.set_visible(show_remote)

    def _on_save(self, _btn) -> None:
        self._error_bar.set_visible(False)

        # 1. Validate connection selection
        if not self._connections:
            self._show_error(_("Please add an SSH connection in the left sidebar first"))
            return
        selected_conn_idx = self._conn_row.get_selected()
        connection = self._connections[selected_conn_idx]

        # 2. Get and validate Bind Port
        bind_port_str = self._bind_port_row.get_text().strip()
        if not bind_port_str:
            self._show_error(_("Bind port cannot be empty"))
            return
        try:
            bind_port = int(bind_port_str)
            if bind_port < 1 or bind_port > 65535:
                raise ValueError
        except ValueError:
            self._show_error(_("Bind port must be an integer between 1 and 65535"))
            return

        # Privilege port check for non-root users
        if bind_port < 1024 and os.getuid() != 0:
            self._show_error(_("Non-root users are not allowed to bind privileged ports below 1024"))
            return

        # 3. Get Rule Type
        selected_type_idx = self._type_row.get_selected()
        rule_type = self._reverse_type_map.get(selected_type_idx, ForwardType.LOCAL)

        # 4. Get and validate Remote Host and Port (if not dynamic)
        remote_host = None
        remote_port = None
        if rule_type != ForwardType.DYNAMIC:
            remote_host = self._remote_host_row.get_text().strip()
            if not remote_host:
                self._show_error(_("Remote host cannot be empty"))
                return

            remote_port_str = self._remote_port_row.get_text().strip()
            if not remote_port_str:
                self._show_error(_("Remote port cannot be empty"))
                return
            try:
                remote_port = int(remote_port_str)
                if remote_port < 1 or remote_port > 65535:
                    raise ValueError
            except ValueError:
                self._show_error(_("Remote port must be an integer between 1 and 65535"))
                return

        bind_addr = self._bind_addr_row.get_text().strip() or "localhost"
        auto_start = self._autostart_row.get_active()

        # Check if local port is free (only for LOCAL and DYNAMIC forwards)
        if rule_type in (ForwardType.LOCAL, ForwardType.DYNAMIC):
            is_same_port = (
                self._is_edit and 
                self._rule and 
                self._rule.bind_port == bind_port and 
                (self._rule.bind_address or "localhost") == (bind_addr or "localhost")
            )
            is_currently_running = (
                self._is_edit and 
                self._rule and 
                self._ssh_service.get_forward_rule_status(self._rule) == "Running"
            )
            
            if not (is_same_port and is_currently_running):
                import socket
                try:
                    addr = bind_addr or "127.0.0.1"
                    if addr == "localhost":
                        addr = "127.0.0.1"
                    infos = socket.getaddrinfo(addr, bind_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for family, socktype, proto, canonname, sockaddr in infos:
                        try:
                            with socket.socket(family, socktype, proto) as s:
                                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                s.bind(sockaddr)
                        except OSError:
                            self._show_error(_("Local port {bind_port} is already in use, please choose another port").format(bind_port=bind_port))
                            return
                except OSError:
                    pass

        # 5. Populate Rule details
        if self._is_edit and self._rule:
            rule = self._rule
            rule.connection_id = connection.id
            rule.type = rule_type
            rule.bind_address = bind_addr
            rule.bind_port = bind_port
            rule.remote_host = remote_host
            rule.remote_port = remote_port
            rule.auto_start = auto_start
        else:
            rule = ForwardRule(
                connection_id=connection.id,
                type=rule_type,
                bind_address=bind_addr,
                bind_port=bind_port,
                remote_host=remote_host,
                remote_port=remote_port,
                enabled=not auto_start,
                auto_start=auto_start,
            )

        # Database save
        db = Database()
        db.open()
        try:
            db.save_forward_rule(rule)
        except ValidationError as e:
            self._show_error(str(e))
            return
        finally:
            db.close()

        if self._callback:
            self._callback(rule)

        self._dialog.close()

    def _show_error(self, message: str) -> None:
        self._error_bar.set_label(message)
        self._error_bar.set_visible(True)


class PortForwardingTab(Gtk.Box):
    """Management interface tab for port forwarding rules."""

    def __init__(self, ssh_service: SSHService) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._ssh_service = ssh_service

        # Dictionary to store mapping from conn_id to Connection names to avoid DB query for each row
        self._conn_names: dict[str, str] = {}
        self._load_connections_map()

        self._build_ui()

        # Listen to SSHService forwarding updates
        self._listener_cb = lambda: GLib.idle_add(self.refresh)
        self._ssh_service.register_forward_rules_listener(self._listener_cb)

        self.refresh()

    @property
    def title(self) -> str:
        return _("Port Forwarding")

    def terminate(self) -> None:
        """Called when this tab is closed to unsubscribe listeners."""
        self._ssh_service.unregister_forward_rules_listener(self._listener_cb)

    def _load_connections_map(self) -> None:
        db = Database()
        db.open()
        try:
            conns = db.list_connections()
            self._conn_names = {c.id: c.name for c in conns}
        finally:
            db.close()

    def _build_ui(self) -> None:
        # Content area stack (list view OR empty state page)
        self._stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=200,
        )

        # Empty state view
        empty_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            vexpand=True,
        )
        empty_title = Gtk.Label(label=_("No port forwarding rules configured"))
        empty_title.add_css_class("title-2")
        empty_title.set_margin_bottom(6)
        empty_box.append(empty_title)

        empty_desc = Gtk.Label(label=_("Add port forwarding rules to forward local or remote ports through SSH tunnels."))
        empty_desc.add_css_class("dim-label")
        empty_box.append(empty_desc)

        empty_add_btn = Gtk.Button(label=_("Add Rule"))
        empty_add_btn.add_css_class("suggested-action")
        empty_add_btn.add_css_class("pill")
        empty_add_btn.set_margin_top(12)
        empty_add_btn.connect("clicked", self._on_add_rule_clicked)
        empty_box.append(empty_add_btn)

        self._stack.add_named(empty_box, "empty")

        # Scrollable list view
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_margin_start(16)
        scroll.set_margin_end(16)
        scroll.set_margin_top(16)
        scroll.set_margin_bottom(16)

        # Clamp the width to keep it beautiful
        clamp = Adw.Clamp()
        clamp.set_maximum_size(700)

        # ListBox
        self._list_box = Gtk.ListBox()
        self._list_box.add_css_class("boxed-list")
        self._list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self._list_box.connect("row-activated", self._on_row_activated)
        clamp.set_child(self._list_box)

        scroll.set_child(clamp)
        self._stack.add_named(scroll, "list")

        self.append(self._stack)

    def _on_row_activated(self, listbox, row) -> None:
        if hasattr(self, "_add_row") and row == self._add_row:
            self._on_add_rule_clicked(None)

    def refresh(self) -> None:
        """Reload all rules from database and refresh UI."""
        self._load_connections_map()

        db = Database()
        db.open()
        try:
            rules = db.list_forward_rules()
        finally:
            db.close()

        # Clear existing rows in ListBox
        while True:
            row = self._list_box.get_row_at_index(0)
            if not row:
                break
            self._list_box.remove(row)

        if not rules:
            self._stack.set_visible_child_name("empty")
            return

        self._stack.set_visible_child_name("list")

        # Add rows for rules
        for rule in rules:
            row_widget = self._create_rule_row(rule)
            self._list_box.append(row_widget)

        # Add the virtual add-rule row at the end
        self._add_row = Gtk.ListBoxRow()
        self._add_row.set_activatable(True)
        self._add_row.set_selectable(False)

        add_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        add_box.set_halign(Gtk.Align.CENTER)
        add_box.set_valign(Gtk.Align.CENTER)
        add_box.set_margin_top(12)
        add_box.set_margin_bottom(12)

        add_icon = Gtk.Image.new_from_icon_name("list-add-symbolic")
        add_icon.add_css_class("dim-label")
        add_box.append(add_icon)
        self._add_row.set_child(add_box)

        self._list_box.append(self._add_row)

    def _create_rule_row(self, rule: ForwardRule) -> Gtk.Widget:
        """Create a redesigned rule row with left color status bar and type badge."""
        status = self._ssh_service.get_forward_rule_status(rule)

        # Status bar CSS class
        _STATUS_BAR = {
            "Running":      "status-bar-running",
            "Disconnected": "status-bar-connecting",
            "Error":        "status-bar-error",
        }
        status_bar_css = _STATUS_BAR.get(status, "status-bar-stopped")

        # Type icon and badge
        _TYPE_ICONS = {
            ForwardType.LOCAL:   "network-transmit-symbolic",
            ForwardType.REMOTE:  "network-receive-symbolic",
            ForwardType.DYNAMIC: "network-vpn-symbolic",
        }
        _TYPE_BADGE_CSS = {
            ForwardType.LOCAL:   "forward-type-local",
            ForwardType.REMOTE:  "forward-type-remote",
            ForwardType.DYNAMIC: "forward-type-dynamic",
        }
        _TYPE_LABELS = {
            ForwardType.LOCAL:   _("Local"),
            ForwardType.REMOTE:  _("Remote"),
            ForwardType.DYNAMIC: _("Dynamic"),
        }

        # Outer row: colored status bar + content
        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        outer.add_css_class("forward-rule-row")

        # Left color status bar
        status_bar = Gtk.Box()
        status_bar.add_css_class(status_bar_css)
        outer.append(status_bar)

        # Inner content area
        inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        inner.set_hexpand(True)
        inner.set_margin_start(12)
        inner.set_margin_end(12)
        inner.set_margin_top(12)
        inner.set_margin_bottom(12)

        # Type icon
        icon = Gtk.Image.new_from_icon_name(
            _TYPE_ICONS.get(rule.type, "network-transmit-receive-symbolic")
        )
        icon.set_pixel_size(20)
        icon.set_valign(Gtk.Align.CENTER)
        inner.append(icon)

        # Text info column
        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        text_box.set_hexpand(True)

        # Connection name + type badge in one row
        name_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        conn_name = self._conn_names.get(rule.connection_id, _("Unknown Connection"))
        title_lbl = Gtk.Label(label=conn_name)
        title_lbl.set_halign(Gtk.Align.START)
        title_lbl.add_css_class("heading")
        name_row.append(title_lbl)

        type_badge = Gtk.Label(label=_TYPE_LABELS.get(rule.type, ""))
        type_badge.add_css_class("forward-type-badge")
        type_badge.add_css_class(_TYPE_BADGE_CSS.get(rule.type, "forward-type-local"))
        name_row.append(type_badge)
        text_box.append(name_row)

        # Detail string
        bind_str = f"{rule.bind_address}:{rule.bind_port}"
        if rule.type == ForwardType.LOCAL:
            detail = f"{bind_str} ➔ {rule.remote_host}:{rule.remote_port}"
        elif rule.type == ForwardType.REMOTE:
            detail = f"{bind_str} ➔ {rule.remote_host}:{rule.remote_port} " + _("(remote side)")
        else:
            detail = _("SOCKS5 proxy on {bind_str}").format(bind_str=bind_str)

        desc_lbl = Gtk.Label(label=detail)
        desc_lbl.set_halign(Gtk.Align.START)
        desc_lbl.add_css_class("caption")
        desc_lbl.add_css_class("dim-label")
        text_box.append(desc_lbl)
        inner.append(text_box)

        # Enable/Disable switch
        sw = Gtk.Switch()
        sw.set_valign(Gtk.Align.CENTER)
        sw.set_active(status == "Running")

        if status == "Error":
            err_msg = self._ssh_service.get_forward_rule_error(rule.id)
            if err_msg:
                sw.set_tooltip_text(_("Error: {err_msg}").format(err_msg=err_msg))
        elif status == "Disconnected" and rule.enabled:
            sw.set_tooltip_text(_("Connecting or disconnected"))

        def _on_switch_state_set(switch, state) -> bool:
            rule.enabled = state
            db = Database()
            db.open()
            try:
                db.save_forward_rule(rule)
            finally:
                db.close()

            if state:
                async def run_start():
                    try:
                        await self._ssh_service.start_forward_rule(rule)
                    except Exception:
                        pass
                self._ssh_service.engine.run_coroutine(run_start())
            else:
                async def run_stop():
                    await self._ssh_service.stop_forward_rule(rule.id)
                self._ssh_service.engine.run_coroutine(run_stop())

            return False

        sw.connect("state-set", _on_switch_state_set)
        inner.append(sw)

        # Edit button
        edit_btn = Gtk.Button(icon_name="document-edit-symbolic")
        edit_btn.add_css_class("flat")
        edit_btn.set_valign(Gtk.Align.CENTER)
        edit_btn.set_tooltip_text(_("Edit"))
        edit_btn.connect("clicked", lambda _: self._on_edit_rule_clicked(rule))
        inner.append(edit_btn)

        # Delete button
        del_btn = Gtk.Button(icon_name="user-trash-symbolic")
        del_btn.add_css_class("flat")
        del_btn.set_valign(Gtk.Align.CENTER)
        del_btn.set_tooltip_text(_("Delete"))
        del_btn.connect("clicked", lambda _: self._on_delete_rule_clicked(rule))
        inner.append(del_btn)

        outer.append(inner)

        # Wrap in list box row
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        row.set_child(outer)
        return row

    def _on_add_rule_clicked(self, _btn) -> None:
        def _on_done(rule: ForwardRule | None) -> None:
            if rule:
                self.refresh()
                # If enabled, try starting
                if rule.enabled:
                    async def run_start():
                        try:
                            await self._ssh_service.start_forward_rule(rule)
                        except Exception:
                            pass
                    self._ssh_service.engine.run_coroutine(run_start())

        PortForwardingDialog(self.get_root(), self._ssh_service, callback=_on_done)

    def _on_edit_rule_clicked(self, rule: ForwardRule) -> None:
        was_running = self._ssh_service.get_forward_rule_status(rule) == "Running"
        def _on_done(updated_rule: ForwardRule | None) -> None:
            if updated_rule:
                self.refresh()
                # Restart the forwarder to apply modified config
                async def run_restart():
                    await self._ssh_service.stop_forward_rule(updated_rule.id)
                    should_start = was_running or (updated_rule.enabled and not updated_rule.auto_start)
                    if should_start:
                        try:
                            await self._ssh_service.start_forward_rule(updated_rule)
                        except Exception:
                            pass
                self._ssh_service.engine.run_coroutine(run_restart())

        PortForwardingDialog(self.get_root(), self._ssh_service, rule=rule, callback=_on_done)

    def _on_delete_rule_clicked(self, rule: ForwardRule) -> None:
        # Prompt / Confirm delete using dialog
        confirm_dialog = Adw.MessageDialog(
            heading=_("Delete Rule"),
            body=_("Are you sure you want to delete this port forwarding rule?"),
        )
        confirm_dialog.add_response("cancel", _("Cancel"))
        confirm_dialog.add_response("delete", _("Delete"))
        confirm_dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        confirm_dialog.set_default_response("delete")
        confirm_dialog.set_close_response("cancel")
        confirm_dialog.set_modal(True)
        confirm_dialog.set_transient_for(self.get_root())

        def _on_response(dialog, response):
            if response == "delete":
                # Stop listener first
                async def do_stop_and_delete():
                    await self._ssh_service.stop_forward_rule(rule.id)
                    db = Database()
                    db.open()
                    try:
                        db.delete_forward_rule(rule.id)
                    finally:
                        db.close()
                    GLib.idle_add(self.refresh)
                self._ssh_service.engine.run_coroutine(do_stop_and_delete())
            dialog.destroy()

        confirm_dialog.connect("response", _on_response)
        confirm_dialog.present()
