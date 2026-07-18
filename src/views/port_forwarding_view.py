# SPDX-License-Identifier: GPL-3.0-or-later

"""Port forwarding management tab view."""

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import os
import logging
from typing import Callable, Any
from gi.repository import Adw, Gtk, Gio, GLib, Gdk, Pango

from db.database import Database
from models.forward_rule import ForwardRule, ForwardType
from models.connection import Connection, ValidationError
from services.ssh_service import SSHService

logger = logging.getLogger(__name__)
import gettext
_ = gettext.gettext


class ForwardRuleCard(Gtk.FlowBoxChild):
    """A card representing a port forwarding rule in the grid."""

    def __init__(
        self,
        rule: ForwardRule,
        conn_name: str,
        status: str,
        error_msg: str | None,
        ssh_service: SSHService,
        remove_callback: Callable[[ForwardRule], None],
    ) -> None:
        super().__init__()
        self.rule = rule
        self._ssh_service = ssh_service
        self._remove_callback = remove_callback

        self.set_size_request(210, -1)
        self.set_halign(Gtk.Align.FILL)
        self.set_margin_start(5)
        self.set_margin_end(5)
        self.set_margin_top(5)
        self.set_margin_bottom(5)
        self.add_css_class("forward-card")

        # Outer container – identical structure to HostCard
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer.add_css_class("host-card-v2")

        _STATUS_STRIPE = {
            "Running":      "forward-stripe-running",
            "Disconnected": "forward-stripe-connecting",
            "Error":        "forward-stripe-error",
        }
        outer.add_css_class(_STATUS_STRIPE.get(status, "forward-stripe-stopped"))
        outer.set_size_request(210, -1)
        outer.set_halign(Gtk.Align.FILL)

        # Card body
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        body.set_margin_start(12)
        body.set_margin_end(12)
        body.set_margin_top(10)
        body.set_margin_bottom(10)

        # Row 1: type icon + connection name + type badge
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)

        _TYPE_ICONS = {
            ForwardType.LOCAL:   "network-transmit-symbolic",
            ForwardType.REMOTE:  "network-receive-symbolic",
            ForwardType.DYNAMIC: "network-vpn-symbolic",
        }
        icon = Gtk.Image.new_from_icon_name(
            _TYPE_ICONS.get(rule.type, "network-transmit-receive-symbolic")
        )
        icon.set_pixel_size(16)
        icon.add_css_class("accent")
        row1.append(icon)

        name_lbl = Gtk.Label(label=conn_name)
        name_lbl.set_halign(Gtk.Align.START)
        name_lbl.set_hexpand(True)
        name_lbl.add_css_class("heading")
        name_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        row1.append(name_lbl)

        _TYPE_LABELS = {
            ForwardType.LOCAL:   _("Local"),
            ForwardType.REMOTE:  _("Remote"),
            ForwardType.DYNAMIC: _("Dynamic"),
        }
        _TYPE_BADGE_CSS = {
            ForwardType.LOCAL:   "forward-type-local",
            ForwardType.REMOTE:  "forward-type-remote",
            ForwardType.DYNAMIC: "forward-type-dynamic",
        }
        badge = Gtk.Label(label=_TYPE_LABELS.get(rule.type, ""))
        badge.add_css_class("forward-type-badge")
        badge.add_css_class(_TYPE_BADGE_CSS.get(rule.type, "forward-type-local"))
        row1.append(badge)
        body.append(row1)

        # Row 2: port detail string (fills body width, ellipsizes like fingerprint-label)
        if rule.type == ForwardType.LOCAL:
            bind_str = f"{rule.bind_address}:{rule.bind_port}"
            detail = f"{bind_str} ➔ {rule.remote_host}:{rule.remote_port}"
        elif rule.type == ForwardType.REMOTE:
            bind_str = f"{rule.bind_address}:{rule.bind_port}"
            detail = f"{bind_str} ➔ {rule.remote_host}:{rule.remote_port}"
        else:
            detail = _("SOCKS5 :{port}").format(port=rule.bind_port)

        detail_lbl = Gtk.Label(label=detail)
        detail_lbl.set_halign(Gtk.Align.FILL)
        detail_lbl.set_width_chars(1)
        detail_lbl.add_css_class("fingerprint-label")
        detail_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        body.append(detail_lbl)

        outer.append(body)
        self.set_child(outer)

        # Setup context menu (Start / Stop / Remove)
        self._setup_context_menu(status)

    def _start_rule(self) -> None:
        """Enable and start the forwarding rule."""
        self.rule.enabled = True
        db = Database()
        db.open()
        try:
            db.save_forward_rule(self.rule)
        finally:
            db.close()

        async def _run():
            try:
                await self._ssh_service.start_forward_rule(self.rule)
            except Exception:
                pass
        self._ssh_service.engine.run_coroutine(_run())

    def _stop_rule(self) -> None:
        """Disable and stop the forwarding rule."""
        self.rule.enabled = False
        db = Database()
        db.open()
        try:
            db.save_forward_rule(self.rule)
        finally:
            db.close()

        async def _run():
            await self._ssh_service.stop_forward_rule(self.rule.id)
        self._ssh_service.engine.run_coroutine(_run())

    def _setup_context_menu(self, status: str) -> None:
        popover = Gtk.PopoverMenu()
        menu_model = Gio.Menu()

        is_running = (status == "Running")
        if is_running:
            menu_model.append(_("Stop"), "cardrow.stop")
        else:
            menu_model.append(_("Start"), "cardrow.start")
        menu_model.append(_("Remove"), "cardrow.remove")

        popover.set_menu_model(menu_model)
        popover.set_parent(self)
        popover.set_has_arrow(False)
        popover.set_position(Gtk.PositionType.BOTTOM)

        action_group = Gio.SimpleActionGroup()

        c_start = Gio.SimpleAction.new("start", None)
        c_start.connect("activate", lambda *_: self._start_rule())
        action_group.add_action(c_start)

        c_stop = Gio.SimpleAction.new("stop", None)
        c_stop.connect("activate", lambda *_: self._stop_rule())
        action_group.add_action(c_stop)

        c_remove = Gio.SimpleAction.new("remove", None)
        c_remove.connect("activate", lambda *_: self._remove_callback(self.rule))
        action_group.add_action(c_remove)

        self.insert_action_group("cardrow", action_group)

        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)

        def _on_right_click(gesture_obj, n_press, x, y):
            flow_box = self.get_parent()
            if flow_box and isinstance(flow_box, Gtk.FlowBox):
                if not self.is_selected():
                    flow_box.unselect_all()
                    flow_box.select_child(self)

            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            popover.set_pointing_to(rect)
            popover.popup()

        gesture.connect("pressed", _on_right_click)
        self.add_controller(gesture)


class JustifiedFlowBox(Gtk.FlowBox):
    """A Gtk.FlowBox subclass that dynamically adjusts card margins to achieve fixed-width justified spacing."""

    def do_size_allocate(self, width: int, height: int, baseline: int) -> None:
        super().do_size_allocate(width, height, baseline)
        self.adjust_margins(width)

    def adjust_margins(self, width: int) -> None:
        children = []
        child = self.get_first_child()
        while child:
            if isinstance(child, Gtk.FlowBoxChild) and child.get_child():
                children.append(child)
            child = child.get_next_sibling()

        if not children:
            return

        w_cell = children[0].get_allocation().width
        if w_cell < 210:
            w_cell = 220

        # Dynamically calculate the maximum columns in a row
        cols = max(1, min(10, width // w_cell))
        if cols <= 1:
            for child in children:
                if child.get_margin_start() != 5 or child.get_margin_end() != 5:
                    child.set_margin_start(5)
                    child.set_margin_end(5)
            return

        cw = 210
        min_m = 5

        for idx, child in enumerate(children):
            col_idx = idx % cols
            delta = max(0, w_cell - cw - 2 * min_m)
            margin_start = min_m + int(round((col_idx / (cols - 1)) * delta))
            margin_end = w_cell - cw - margin_start

            # Dampen updates to prevent infinite loop of size-allocate signals
            if child.get_margin_start() != margin_start or child.get_margin_end() != margin_end:
                child.set_margin_start(margin_start)
                child.set_margin_end(margin_end)


class PortForwardingTab(Gtk.Box):
    """Management interface tab for port forwarding rules."""

    def __init__(self, ssh_service: SSHService) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL)
        self._ssh_service = ssh_service

        self._connections: list[Connection] = []
        self._editing_rule: ForwardRule | None = None

        # Dictionary to store mapping from conn_id to Connection names
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
        # Left Panel (Grid + Actions Bar)
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        left_box.set_hexpand(True)

        # Actions Bar
        actions_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions_bar.set_margin_start(16)
        actions_bar.set_margin_end(16)
        actions_bar.set_margin_top(12)
        actions_bar.set_margin_bottom(12)

        # Search Entry
        self._search_entry = Gtk.SearchEntry(placeholder_text=_("Search rules…"))
        self._search_entry.set_size_request(240, -1)
        self._search_entry.connect("search-changed", self._on_search_changed)
        actions_bar.append(self._search_entry)

        actions_spacer = Gtk.Box()
        actions_spacer.set_hexpand(True)
        actions_bar.append(actions_spacer)

        # + New Rule button
        new_rule_btn = Gtk.Button(label=_("New Rule"))
        new_rule_btn.add_css_class("suggested-action")
        new_rule_btn.connect("clicked", lambda _: self.show_editor(None))
        actions_bar.append(new_rule_btn)

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
        self._flow_box = JustifiedFlowBox()
        self._flow_box.set_valign(Gtk.Align.START)
        self._flow_box.set_max_children_per_line(10)
        self._flow_box.set_homogeneous(True)
        self._flow_box.set_min_children_per_line(1)
        self._flow_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
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
        empty_icon = Gtk.Image.new_from_icon_name("network-transmit-receive-symbolic")
        empty_icon.set_pixel_size(48)
        empty_icon.set_opacity(0.3)
        empty_box.append(empty_icon)

        empty_label = Gtk.Label(label=_("No Forwarding Rules"))
        empty_label.add_css_class("title-2")
        empty_box.append(empty_label)

        empty_desc = Gtk.Label(label=_("Click 'New Rule' to configure port forwarding rules."))
        empty_desc.add_css_class("dim-label")
        empty_box.append(empty_desc)
        
        self._left_stack.add_named(empty_box, "empty")
        left_box.append(self._left_stack)

        self.append(left_box)

        # Separator
        self._sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        self._sep.set_visible(False)
        self.append(self._sep)

        # Right Panel (Inline Editor)
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

        # Header of Editor
        right_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        right_header.set_margin_start(16)
        right_header.set_margin_end(16)
        right_header.set_margin_top(12)
        right_header.set_margin_bottom(12)

        self._right_title = Gtk.Label()
        self._right_title.add_css_class("title-2")
        right_header.append(self._right_title)

        right_spacer = Gtk.Box()
        right_spacer.set_hexpand(True)
        right_header.append(right_spacer)

        close_btn = Gtk.Button(icon_name="window-close-symbolic")
        close_btn.add_css_class("flat")
        close_btn.connect("clicked", lambda _: self._close_right_panel())
        right_header.append(close_btn)
        self._right_panel.append(right_header)

        # Form Scrollable area
        self._build_editor_ui()
        self.append(self._right_clamp)

    def _build_editor_ui(self) -> None:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_margin_start(16)
        scroll.set_margin_end(16)
        scroll.set_margin_bottom(16)

        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        pref_group = Adw.PreferencesGroup()
        pref_group.add_css_class("editor-page")

        # 1. SSH Connection Selection
        self._conn_row = Adw.ComboRow(title=_("SSH Connection"))
        pref_group.add(self._conn_row)

        # 2. Forwarding Type selection
        type_options = [_("Local Forwarding (-L)"), _("Remote Forwarding (-R)"), _("Dynamic Forwarding (-D SOCKS5)")]
        type_list = Gtk.StringList.new(type_options)
        self._type_row = Adw.ComboRow(title=_("Forward Type"), model=type_list)
        self._type_map = {
            ForwardType.LOCAL: 0,
            ForwardType.REMOTE: 1,
            ForwardType.DYNAMIC: 2,
        }
        self._reverse_type_map = {v: k for k, v in self._type_map.items()}
        pref_group.add(self._type_row)

        # 3. Bind Address
        self._bind_addr_row = Adw.EntryRow(title=_("Bind Address (Default: localhost)"))
        pref_group.add(self._bind_addr_row)

        # 4. Bind Port
        self._bind_port_row = Adw.EntryRow(title=_("Bind Port"))
        pref_group.add(self._bind_port_row)

        # 5. Remote Host
        self._remote_host_row = Adw.EntryRow(title=_("Remote Host"))
        pref_group.add(self._remote_host_row)

        # 6. Remote Port
        self._remote_port_row = Adw.EntryRow(title=_("Remote Port"))
        pref_group.add(self._remote_port_row)

        # 7. Auto Start
        self._autostart_row = Adw.SwitchRow(title=_("Automatically connect on app launch"))
        pref_group.add(self._autostart_row)

        form_box.append(pref_group)

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

        # Remove Button (shown only when editing)
        self._remove_btn = Gtk.Button(label=_("Remove Rule"))
        self._remove_btn.add_css_class("destructive-action")
        self._remove_btn.add_css_class("pill")
        self._remove_btn.set_margin_top(12)
        self._remove_btn.connect("clicked", self._on_remove_clicked_from_form)
        form_box.append(self._remove_btn)

        scroll.set_child(form_box)
        self._right_panel.append(scroll)

        # Connect signals
        self._type_row.connect("notify::selected", self._on_type_changed)

    def _on_type_changed(self, *args) -> None:
        selected_idx = self._type_row.get_selected()
        rule_type = self._reverse_type_map.get(selected_idx, ForwardType.LOCAL)
        show_remote = (rule_type != ForwardType.DYNAMIC)
        self._remote_host_row.set_visible(show_remote)
        self._remote_port_row.set_visible(show_remote)

    def _show_error(self, message: str) -> None:
        self._error_bar.set_label(message)
        self._error_bar.set_visible(True)

    def show_editor(self, rule: ForwardRule | None = None) -> None:
        self._editing_rule = rule
        is_edit = rule is not None

        # Fetch connections to populate connection selection row
        db = Database()
        db.open()
        try:
            self._connections = db.list_connections()
        finally:
            db.close()

        conn_names = [c.name for c in self._connections]
        if not conn_names:
            conn_names = [_("No SSH connections available")]
        string_list = Gtk.StringList.new(conn_names)
        self._conn_row.set_model(string_list)

        self._error_bar.set_visible(False)

        if is_edit and rule:
            self._right_title.set_label(_("Edit Port Forwarding"))
            
            # Select connection
            for idx, c in enumerate(self._connections):
                if c.id == rule.connection_id:
                    self._conn_row.set_selected(idx)
                    break
            
            self._type_row.set_selected(self._type_map.get(rule.type, 0))
            self._bind_addr_row.set_text(rule.bind_address)
            self._bind_port_row.set_text(str(rule.bind_port))
            self._remote_host_row.set_text(rule.remote_host or "localhost")
            self._remote_port_row.set_text(str(rule.remote_port) if rule.remote_port is not None else "")
            self._autostart_row.set_active(rule.auto_start)
            
            self._remove_btn.set_visible(True)
        else:
            self._right_title.set_label(_("New Port Forwarding"))
            self._conn_row.set_selected(0)
            self._type_row.set_selected(0)
            self._bind_addr_row.set_text("localhost")
            self._bind_port_row.set_text("")
            self._remote_host_row.set_text("localhost")
            self._remote_port_row.set_text("")
            self._autostart_row.set_active(False)
            
            self._remove_btn.set_visible(False)

        self._on_type_changed()
        self._right_clamp.set_visible(True)
        self._sep.set_visible(True)

    def _close_right_panel(self) -> None:
        self._right_clamp.set_visible(False)
        self._sep.set_visible(False)
        self._flow_box.unselect_all()

    def _on_search_changed(self, _entry: Gtk.SearchEntry) -> None:
        self.refresh()

    def refresh(self) -> None:
        """Reload all rules from database and refresh UI."""
        self._load_connections_map()

        db = Database()
        db.open()
        try:
            rules = db.list_forward_rules()
        finally:
            db.close()

        # Filter rules by search text if present
        query = self._search_entry.get_text().strip().lower()
        if query:
            filtered = []
            for r in rules:
                conn_name = self._conn_names.get(r.connection_id, "").lower()
                bind_str = f"{r.bind_address}:{r.bind_port}".lower()
                remote_str = f"{r.remote_host}:{r.remote_port}".lower() if r.remote_host else ""
                type_str = r.type.value.lower()
                if (query in conn_name or
                    query in bind_str or
                    query in remote_str or
                    query in type_str):
                    filtered.append(r)
        else:
            filtered = rules

        # Clear existing cards in FlowBox
        while True:
            child = self._flow_box.get_child_at_index(0)
            if child is None:
                break
            self._flow_box.remove(child)

        if not filtered:
            self._left_stack.set_visible_child_name("empty")
            self._close_right_panel()
            return

        self._left_stack.set_visible_child_name("grid")

        # Add cards for rules
        for rule in filtered:
            status = self._ssh_service.get_forward_rule_status(rule)
            error_msg = self._ssh_service.get_forward_rule_error(rule.id)
            conn_name = self._conn_names.get(rule.connection_id, _("Unknown Connection"))
            
            card = ForwardRuleCard(
                rule=rule,
                conn_name=conn_name,
                status=status,
                error_msg=error_msg,
                ssh_service=self._ssh_service,
                remove_callback=self._on_remove_rule_clicked
            )
            self._flow_box.append(card)

    def _on_card_activated(self, _flow_box: Gtk.FlowBox, card: ForwardRuleCard) -> None:
        self.show_editor(card.rule)

    def _on_selection_changed(self, _flow_box: Gtk.FlowBox) -> None:
        selected = self._flow_box.get_selected_children()
        if not selected:
            if self._editing_rule is not None:
                self._close_right_panel()
        else:
            self.show_editor(selected[0].rule)

    def _on_save_clicked(self, _btn) -> None:
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
        is_edit = self._editing_rule is not None
        if rule_type in (ForwardType.LOCAL, ForwardType.DYNAMIC):
            is_same_port = (
                is_edit and 
                self._editing_rule and 
                self._editing_rule.bind_port == bind_port and 
                (self._editing_rule.bind_address or "localhost") == (bind_addr or "localhost")
            )
            is_currently_running = (
                is_edit and 
                self._editing_rule and 
                self._ssh_service.get_forward_rule_status(self._editing_rule) == "Running"
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
        if is_edit and self._editing_rule:
            rule = self._editing_rule
            was_running = self._ssh_service.get_forward_rule_status(rule) == "Running"
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
            was_running = False

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

        # Apply rule status change / restart forwarder
        if is_edit:
            async def run_restart():
                await self._ssh_service.stop_forward_rule(rule.id)
                should_start = was_running or (rule.enabled and not rule.auto_start)
                if should_start:
                    try:
                        await self._ssh_service.start_forward_rule(rule)
                    except Exception:
                        pass
            self._ssh_service.engine.run_coroutine(run_restart())
        else:
            if rule.enabled:
                async def run_start():
                    try:
                        await self._ssh_service.start_forward_rule(rule)
                    except Exception:
                        pass
                self._ssh_service.engine.run_coroutine(run_start())

        self.refresh()
        self._close_right_panel()
        
        msg = _("Updated: {name}") if is_edit else _("Added: {name}")
        self._show_toast(msg.format(name=f"{connection.name} ({rule.bind_port})"))

    def _on_remove_rule_clicked(self, rule: ForwardRule) -> None:
        # Prompt / Confirm remove using dialog
        confirm_dialog = Adw.MessageDialog(
            heading=_("Remove Rule"),
            body=_("Are you sure you want to remove this port forwarding rule?"),
        )
        confirm_dialog.add_response("cancel", _("Cancel"))
        confirm_dialog.add_response("remove", _("Remove"))
        confirm_dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        confirm_dialog.set_default_response("remove")
        confirm_dialog.set_close_response("cancel")
        confirm_dialog.set_modal(True)
        confirm_dialog.set_transient_for(self.get_root())

        def _on_response(dialog, response):
            if response == "remove":
                async def do_stop_and_remove():
                    await self._ssh_service.stop_forward_rule(rule.id)
                    db = Database()
                    db.open()
                    try:
                        db.delete_forward_rule(rule.id)
                    finally:
                        db.close()
                    GLib.idle_add(self.refresh)
                self._ssh_service.engine.run_coroutine(do_stop_and_remove())
                self._close_right_panel()
            dialog.destroy()

        confirm_dialog.connect("response", _on_response)
        confirm_dialog.present()

    def _on_remove_clicked_from_form(self, _btn) -> None:
        if self._editing_rule:
            self._on_remove_rule_clicked(self._editing_rule)

    def _show_toast(self, msg: str) -> None:
        root = self.get_root()
        if root and hasattr(root, "_show_toast"):
            root._show_toast(msg)
        else:
            logger.info(f"Toast: {msg}")
