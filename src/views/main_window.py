# SPDX-License-Identifier: GPL-3.0-or-later

"""Main application window — sidebar navigation + terminal split view."""

from __future__ import annotations

import gettext
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk

from db.database import Database
from models.connection import AuthMethod, Connection, ValidationError
from services.ssh_service import SSHService
from services.vault_manager import VaultManager
from utils.secure import SecureBytes
from views.hosts_view import HostsPage
from views.keychain_view import KeychainPage
from views.port_forwarding_view import PortForwardingTab
from views.terminal_view import TerminalTabView
from views.vault_settings_dialog import VaultManagerWindow

_ = gettext.gettext
logger = logging.getLogger(__name__)


class SentinelWindow(Adw.ApplicationWindow):
    """Main window with category sidebar and stack content pages."""

    def __init__(self, **kwargs) -> None:
        super().__init__(
            default_width=1100,
            default_height=700,
            title=_("Sentinel"),
            **kwargs,
        )

        # Core services
        self._db = Database()
        self._db.open()
        self._ssh_service = SSHService()
        self._ssh_service.register_main_window(self)

        # Build UI
        self._build_ui()
        self._setup_shortcuts()

        # Check startup vault status
        vm = VaultManager.get()
        if not vm.is_unlocked:
            self._main_stack.set_visible_child_name("unlock")
            if not vm.is_initialized:
                self._unlock_stack.set_visible_child_name("setup")
            else:
                self._unlock_stack.set_visible_child_name("unlock")
        else:
            self._main_stack.set_visible_child_name("main_ui")
            self._load_connections()
            self._ssh_service.auto_start_forward_rules()

    # ── UI Construction ───────────────────────────────────────

    def _build_ui(self) -> None:
        self._main_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=250,
        )

        # Page 1: Unlock / Setup Screen
        unlock_screen = self._build_unlock_screen()
        self._main_stack.add_named(unlock_screen, "unlock")

        # Page 2: Main Application UI
        main_ui = self._build_main_ui()
        self._main_stack.add_named(main_ui, "main_ui")

        self.set_content(self._main_stack)

    def _build_unlock_screen(self) -> Gtk.Widget:
        # Card container to hold the forms
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        card.add_css_class("unlock-card")
        card.set_margin_start(20)
        card.set_margin_end(20)
        card.set_margin_top(20)
        card.set_margin_bottom(20)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(440)
        clamp.set_halign(Gtk.Align.CENTER)
        clamp.set_valign(Gtk.Align.CENTER)
        clamp.set_vexpand(True)
        clamp.set_child(card)

        # Stack for Setup vs Unlock
        self._unlock_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=250,
        )

        # ── Setup Sub-page (First time initialization) ──
        setup_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        setup_box.set_margin_start(24)
        setup_box.set_margin_end(24)
        setup_box.set_margin_top(24)
        setup_box.set_margin_bottom(24)

        s_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        s_icon.set_pixel_size(48)
        s_icon.add_css_class("accent")
        setup_box.append(s_icon)

        s_title = Gtk.Label(label=_("Create Secure Vault"))
        s_title.add_css_class("title-1")
        setup_box.append(s_title)

        s_desc = Gtk.Label(
            label=_("Choose a master password to protect and encrypt all your connection details and SSH keys on disk."),
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        s_desc.add_css_class("dim-label")
        setup_box.append(s_desc)

        s_list = Gtk.ListBox()
        s_list.add_css_class("boxed-list")
        self._setup_pw = Adw.PasswordEntryRow(title=_("Master Password"))
        self._setup_confirm = Adw.PasswordEntryRow(title=_("Confirm Password"))
        s_list.append(self._setup_pw)
        s_list.append(self._setup_confirm)
        setup_box.append(s_list)

        s_btn = Gtk.Button(label=_("Create Vault"))
        s_btn.add_css_class("suggested-action")
        s_btn.add_css_class("pill")
        s_btn.connect("clicked", self._on_setup_vault_clicked)
        setup_box.append(s_btn)

        self._unlock_stack.add_named(setup_box, "setup")

        # ── Unlock Sub-page (Subsequent launches) ──
        unlock_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        unlock_box.set_margin_start(24)
        unlock_box.set_margin_end(24)
        unlock_box.set_margin_top(24)
        unlock_box.set_margin_bottom(24)

        u_icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
        u_icon.set_pixel_size(48)
        u_icon.add_css_class("warning")
        unlock_box.append(u_icon)

        u_title = Gtk.Label(label=_("Unlock Sentinel"))
        u_title.add_css_class("title-1")
        unlock_box.append(u_title)

        u_desc = Gtk.Label(
            label=_("Enter your Sentinel vault master password to continue."),
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        u_desc.add_css_class("dim-label")
        unlock_box.append(u_desc)

        u_list = Gtk.ListBox()
        u_list.add_css_class("boxed-list")
        self._unlock_pw = Adw.PasswordEntryRow(title=_("Master Password"))
        u_list.append(self._unlock_pw)
        unlock_box.append(u_list)

        u_btn = Gtk.Button(label=_("Unlock"))
        u_btn.add_css_class("suggested-action")
        u_btn.add_css_class("pill")
        u_btn.connect("clicked", self._on_unlock_vault_clicked)
        self._unlock_pw.connect("entry-activated", self._on_unlock_vault_clicked)
        unlock_box.append(u_btn)

        # Reset helper option
        reset_lbl = Gtk.Label(label=_("Forgot your master password?"))
        reset_lbl.add_css_class("caption")
        reset_lbl.add_css_class("dim-label")
        reset_lbl.set_margin_top(16)
        unlock_box.append(reset_lbl)

        reset_btn = Gtk.Button(label=_("Reset & Erase Everything"))
        reset_btn.add_css_class("flat")
        reset_btn.add_css_class("destructive-action")
        reset_btn.connect("clicked", self._on_reset_vault_clicked)
        unlock_box.append(reset_btn)

        self._unlock_stack.add_named(unlock_box, "unlock")

        card.append(self._unlock_stack)

        self._unlock_toast_overlay = Adw.ToastOverlay()
        self._unlock_toast_overlay.set_child(clamp)

        # Main box wrapper to give a modern dark / themed background
        outer_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        outer_box.set_hexpand(True)
        outer_box.set_vexpand(True)
        # Add a subtle background color class
        outer_box.add_css_class("view")
        outer_box.append(self._unlock_toast_overlay)

        return outer_box

    def _get_settings_path(self) -> str:
        config_dir = os.path.join(GLib.get_user_config_dir(), "sentinel")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "ui_settings.json")

    def _load_sidebar_state(self) -> bool:
        path = self._get_settings_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("sidebar_expanded", True)
            except Exception:
                pass
        return True

    def _save_sidebar_state(self, expanded: bool) -> None:
        path = self._get_settings_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"sidebar_expanded": expanded}, f)
        except Exception:
            pass

    def _build_main_ui(self) -> Gtk.Widget:
        # Toast overlay wraps split view
        self._toast_overlay = Adw.ToastOverlay()

        initial_expanded = self._load_sidebar_state()

        # Split view: sidebar + content stack
        self._split_view = Adw.NavigationSplitView()
        self._split_view.set_min_sidebar_width(260 if initial_expanded else 52)
        self._split_view.set_max_sidebar_width(320 if initial_expanded else 52)

        # ─── Sidebar ─────────────────────────────────────────
        sidebar_page = Adw.NavigationPage(title=_("Sentinel"))
        sidebar_widget = self._build_navigation_sidebar(initial_expanded)
        sidebar_page.set_child(sidebar_widget)

        # ─── Content Area Stack ──────────────────────────────
        content_page = Adw.NavigationPage(title=_("Sentinel"))
        content_toolbar = Adw.ToolbarView()

        # Content pages Gtk.Stack
        self._content_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=200,
        )

        # 1. Hosts page
        self._hosts_page = HostsPage(
            self,
            connect_callback=self._connect_to,
            edit_callback=self.show_connection_editor,
            sftp_callback=self._open_sftp_for,
            delete_callback=self._on_delete_selected,
            clear_host_key_callback=self._on_clear_host_key,
        )
        self._content_stack.add_named(self._hosts_page, "hosts")

        # 2. Terminal tab area
        self._terminal_tab_view = TerminalTabView(self._ssh_service)
        self._content_stack.add_named(self._terminal_tab_view.widget, "terminals")

        # 3. Keychain page
        self._keychain_page = KeychainPage(self)
        self._content_stack.add_named(self._keychain_page, "keychain")

        # 4. Port Forwarding page
        self._port_forwarding_tab = PortForwardingTab(self._ssh_service)
        self._content_stack.add_named(self._port_forwarding_tab, "port_forwarding")

        # 5. Vault Settings page (embedded Gtk.Box view)
        self._vault_settings_tab = VaultManagerWindow(app=self.get_application())
        self._content_stack.add_named(self._vault_settings_tab, "vault_settings")

        # ─── Header Bar & Tab Bar ───
        content_header = Adw.HeaderBar()
        self._window_title = Adw.WindowTitle(title=_("Hosts"), subtitle="")
        content_header.set_title_widget(self._window_title)

        # Utilise native Adw.TabBar for bulletproof tabs
        self._tab_bar = Adw.TabBar()
        self._tab_bar.set_view(self._terminal_tab_view.tab_view)
        self.insert_action_group("tab", self._terminal_tab_view._tab_actions)
        self._tab_bar.set_autohide(False)
        self._tab_bar.set_expand_tabs(True)
        self._terminal_tab_view.tab_view.connect("create-window", self._create_new_window_for_tab)

        # Local Shell Button
        shell_btn = Gtk.Button(
            icon_name="computer-symbolic",
            tooltip_text=_("Open Local Shell (Ctrl+T)")
        )
        shell_btn.add_css_class("flat")
        shell_btn.set_valign(Gtk.Align.CENTER)
        shell_btn.connect("clicked", lambda _: self._open_local_shell())
        content_header.pack_end(shell_btn)

        # Merge secondary window tab button
        self._merge_btn = Gtk.Button(
            icon_name="list-remove-symbolic",
            tooltip_text=_("Merge all tabs into another window and close")
        )
        self._merge_btn.add_css_class("flat")
        self._merge_btn.set_valign(Gtk.Align.CENTER)
        self._merge_btn.connect("clicked", lambda _: self._merge_all_to_other_window())
        self._tab_bar.set_end_action_widget(self._merge_btn)

        # Tab listeners
        self._terminal_tab_view.tab_view.connect("notify::selected-page", self._on_selected_page_changed)
        self._terminal_tab_view.tab_view.connect("page-attached", self._on_page_attached)
        self._terminal_tab_view.tab_view.connect("notify::n-pages", self._on_tabs_changed)

        GLib.timeout_add(1000, self._refresh_merge_button_visibility)

        # Only show TabBar when viewing the "Terminals" tab
        # Only show TabBar when viewing the "Terminals" tab & update key capture for search entries
        def _on_stack_visible_child_changed(stack, _pspec):
            active_child = stack.get_visible_child_name()
            self._tab_bar.set_visible(active_child == "terminals")

            # Reset key capture for all search entries to prevent inactive pages from intercepting keys
            for page in [self._hosts_page, self._keychain_page, self._port_forwarding_tab]:
                if hasattr(page, "_search_entry") and page._search_entry:
                    page._search_entry.set_key_capture_widget(None)

            # Assign key capture to the currently active page's search entry
            active_page = stack.get_visible_child()
            if active_page and hasattr(active_page, "_search_entry") and active_page._search_entry:
                active_page._search_entry.set_key_capture_widget(self)

        self._content_stack.connect("notify::visible-child", _on_stack_visible_child_changed)
        self._tab_bar.set_visible(False)

        content_toolbar.add_top_bar(content_header)
        content_toolbar.add_top_bar(self._tab_bar)

        self._content_stack.set_visible_child_name("hosts")
        content_toolbar.set_content(self._content_stack)
        content_page.set_child(content_toolbar)

        # ─── Assemble ────────────────────────────────────────
        self._split_view.set_sidebar(sidebar_page)
        self._split_view.set_content(content_page)

        # Responsive breakpoint
        bp = Adw.Breakpoint()
        bp.set_condition(Adw.BreakpointCondition.parse("max-width: 600sp"))
        bp.add_setter(self._split_view, "collapsed", True)
        self.add_breakpoint(bp)

        self._toast_overlay.set_child(self._split_view)

        # Select the default Hosts row in the sidebar
        self._on_nav_btn_clicked("hosts")

        self._update_sidebar_css(initial_expanded)

        return self._toast_overlay

    def _build_navigation_sidebar(self, initial_expanded: bool) -> Gtk.Widget:
        sidebar_toolbar = Adw.ToolbarView()

        # ── Header: CenterBox guarantees the button is always centered ─────────
        # Using Gtk.CenterBox (not Adw.HeaderBar, not Gtk.Box) because it
        # structurally centers its center-widget regardless of sidebar width.
        self._sidebar_header_cb = Gtk.CenterBox()
        self._sidebar_header_cb.add_css_class("sidebar-header-box")
        self._sidebar_header_cb.set_hexpand(True)

        self._collapse_btn = Gtk.ToggleButton(
            icon_name="sidebar-show-symbolic",
            tooltip_text=_("Collapse Sidebar"),
            active=initial_expanded,
        )
        self._collapse_btn.add_css_class("flat")
        self._collapse_btn.set_valign(Gtk.Align.CENTER)
        self._collapse_btn.add_css_class("sidebar-action-btn")
        self._collapse_btn.connect("toggled", self._on_collapse_toggled)
        self._sidebar_header_cb.set_start_widget(self._collapse_btn)
        sidebar_toolbar.add_top_bar(self._sidebar_header_cb)

        # ── Nav buttons (Box + Button, no ListBox) ────────────
        # Using plain Gtk.Button in a Gtk.Box instead of ListBox+ListBoxRow
        # gives us full layout control for collapsed icon-rail alignment.
        self._nav_btn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._nav_btn_box.set_vexpand(True)

        # State tracking
        self._nav_rows: dict[str, Gtk.Button] = {}       # page_id -> button
        self._nav_labels: dict[str, Gtk.Label] = {}      # page_id -> label
        self._nav_stacks: dict[str, Gtk.Stack] = {}      # page_id -> stack widget
        self._nav_current: str = "hosts"

        nav_items = [
            ("network-server-symbolic",           _("Hosts"),           "hosts"),
            ("utilities-terminal-symbolic",        _("Terminals"),       "terminals"),
            ("dialog-password-symbolic",           _("Keychain"),        "keychain"),
            ("network-transmit-receive-symbolic",  _("Port Forwarding"), "port_forwarding"),
            ("emblem-system-symbolic",             _("Vault Settings"),  "vault_settings"),
        ]
        for icon_name, label_text, page_id in nav_items:
            btn = self._create_nav_row(icon_name, label_text, page_id)
            self._nav_btn_box.append(btn)
            self._nav_rows[page_id] = btn

        self._nav_rows["terminals"].set_visible(False)  # Hidden until a tab opens

        nav_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._nav_btn_box.set_margin_top(8)
        nav_vbox.append(self._nav_btn_box)
        nav_vbox.set_vexpand(True)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(nav_vbox)
        sidebar_toolbar.set_content(scroll)

        # ── Bottom bar: CenterBox guarantees menu button is always centered ────
        self._sidebar_bottom_cb = Gtk.CenterBox()
        self._sidebar_bottom_cb.add_css_class("sidebar-bottom-bar")
        self._sidebar_bottom_cb.set_hexpand(True)

        menu_model = Gio.Menu()
        menu_model.append(_("Terminal Theme"), "app.terminal_theme")
        menu_model.append(_("About Sentinel"), "app.about")
        menu_model.append(_("Quit"), "app.quit")

        self._menu_btn = Gtk.MenuButton(
            icon_name="open-menu-symbolic",
            tooltip_text=_("Menu"),
            direction=Gtk.ArrowType.UP,
        )
        self._menu_btn.add_css_class("flat")
        self._menu_btn.set_menu_model(menu_model)
        self._menu_btn.set_valign(Gtk.Align.CENTER)
        self._menu_btn.add_css_class("sidebar-action-btn")
        self._menu_btn.add_css_class("footer-expanded")
        self._menu_btn.set_always_show_arrow(False)
        self._sidebar_bottom_cb.set_start_widget(self._menu_btn)

        sidebar_toolbar.add_bottom_bar(self._sidebar_bottom_cb)

        return sidebar_toolbar

    def _create_nav_row(self, icon_name: str, label_text: str, page_id: str) -> Gtk.Button:
        """Create a nav button that centres its icon reliably in both modes using a Stack."""
        btn = Gtk.Button()
        btn.add_css_class("nav-item")
        btn.add_css_class("flat")
        btn.set_hexpand(True)

        stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=250,
            hhomogeneous=False,
        )
        stack.set_halign(Gtk.Align.START)

        # --- Expanded state ---
        icon_exp = Gtk.Image.new_from_icon_name(icon_name)
        icon_exp.set_pixel_size(18)
        lbl = Gtk.Label(label=label_text)
        lbl.set_halign(Gtk.Align.START)
        lbl.set_hexpand(True)

        box_exp = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box_exp.append(icon_exp)
        box_exp.append(lbl)
        
        stack.add_named(box_exp, "expanded")

        # --- Collapsed state ---
        icon_coll = Gtk.Image.new_from_icon_name(icon_name)
        icon_coll.set_pixel_size(18)
        icon_coll.set_halign(Gtk.Align.CENTER)
        icon_coll.set_valign(Gtk.Align.CENTER)
        
        stack.add_named(icon_coll, "collapsed")

        # Set default
        stack.set_visible_child_name("expanded")

        btn.set_child(stack)
        btn.connect("clicked", lambda _b, pid=page_id: self._on_nav_btn_clicked(pid))

        # Store references for collapse toggling
        self._nav_labels[page_id] = lbl
        self._nav_stacks[page_id] = stack

        return btn

    # ── Sidebar Collapse (icon-only rail) ────────────────────

    def _update_sidebar_css(self, expanded: bool) -> None:
        if hasattr(self, "_sidebar_header_cb"):
            if expanded:
                self._collapse_btn.remove_css_class("header-collapsed")
                self._collapse_btn.add_css_class("header-expanded")
                self._menu_btn.remove_css_class("footer-collapsed")
                self._menu_btn.add_css_class("footer-expanded")
            else:
                self._collapse_btn.remove_css_class("header-expanded")
                self._collapse_btn.add_css_class("header-collapsed")
                self._menu_btn.remove_css_class("footer-expanded")
                self._menu_btn.add_css_class("footer-collapsed")

        for page_id, btn in self._nav_rows.items():
            stack = self._nav_stacks.get(page_id)
            if stack is not None:
                stack.set_visible_child_name("expanded" if expanded else "collapsed")

            if expanded:
                btn.remove_css_class("nav-collapsed-item")
            else:
                btn.add_css_class("nav-collapsed-item")

        if expanded:
            self._nav_btn_box.remove_css_class("nav-collapsed")
        else:
            self._nav_btn_box.add_css_class("nav-collapsed")

    def _on_collapse_toggled(self, btn: Gtk.ToggleButton) -> None:
        """Toggle between full sidebar (icon+label) and icon-only rail."""
        expanded = btn.get_active()
        self._save_sidebar_state(expanded)
        self._update_sidebar_css(expanded)

        if hasattr(self, "_split_view"):
            from_w = self._split_view.get_min_sidebar_width()
            to_w = 260 if expanded else 52
            self._animate_sidebar_width(from_w, to_w)

    def _animate_sidebar_width(self, from_w: float, to_w: float) -> None:
        if hasattr(self, "_sidebar_animation") and self._sidebar_animation.get_state() == Adw.AnimationState.PLAYING:
            self._sidebar_animation.skip()

        target = Adw.CallbackAnimationTarget.new(self._on_sidebar_animation_step)
        
        self._sidebar_animation = Adw.TimedAnimation.new(
            self._split_view,
            from_w,
            to_w,
            250,
            target
        )
        self._sidebar_animation.set_easing(Adw.Easing.EASE_IN_OUT_CUBIC)
        self._sidebar_animation.play()

    def _on_sidebar_animation_step(self, value: float, *args) -> None:
        w = int(value)
        self._split_view.set_max_sidebar_width(w)
        self._split_view.set_min_sidebar_width(w)

    def _on_nav_btn_clicked(self, page_id: str) -> None:
        """Handle nav button click: update selection highlight and switch page."""
        # Remove selected from old button
        old_btn = self._nav_rows.get(self._nav_current)
        if old_btn:
            old_btn.remove_css_class("selected")
        # Apply selected to new button
        new_btn = self._nav_rows.get(page_id)
        if new_btn:
            new_btn.add_css_class("selected")
        self._nav_current = page_id

        self._content_stack.set_visible_child_name(page_id)
        titles = {
            "hosts":           _("Hosts"),
            "terminals":       _("Terminals"),
            "keychain":        _("Keychain"),
            "port_forwarding": _("Port Forwarding"),
            "vault_settings":  _("Vault Settings"),
        }
        self._window_title.set_title(titles.get(page_id, _("Sentinel")))
        self._window_title.set_subtitle("")

    # ── Local Vault Actions ───────────────────────────────────

    def _on_setup_vault_clicked(self, _btn) -> None:
        pwd = self._setup_pw.get_text()
        confirm = self._setup_confirm.get_text()
        if not pwd:
            self._show_unlock_toast(_("Please enter a master password."))
            return
        if pwd != confirm:
            self._show_unlock_toast(_("Passwords do not match."))
            return
        if len(pwd) < 8:
            self._show_unlock_toast(_("Password must be at least 8 characters."))
            return

        pwd_sb = SecureBytes(pwd)
        try:
            VaultManager.get().initialize(pwd_sb)
            pwd_sb.clear()
            self._show_toast(_("Secure Vault initialized."))
            self._on_successful_unlock()
        except Exception as e:
            pwd_sb.clear()
            self._show_unlock_toast(_("Failed to initialize vault: {e}").format(e=e))

    def _on_unlock_vault_clicked(self, _btn) -> None:
        pwd = self._unlock_pw.get_text()
        if not pwd:
            return
        pwd_sb = SecureBytes(pwd)
        ok = VaultManager.get().unlock(pwd_sb)
        pwd_sb.clear()

        if ok:
            self._unlock_pw.set_text("")
            self._on_successful_unlock()
        else:
            self._show_unlock_toast(_("Wrong master password."))

    def _on_reset_vault_clicked(self, _btn) -> None:
        dialog = Adw.AlertDialog(
            heading=_("Reset & Erase Everything?"),
            body=_("This will permanently erase all connections and SSH keys inside your Sentinel secure vault. This cannot be undone."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("reset", _("Erase All"))
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def _on_resp(_d, resp):
            if resp == "reset":
                VaultManager.get().destroy_vault()
                VaultManager.get()._vault.open()
                self._show_unlock_toast(_("Sentinel erased. Please configure a new master password."))
                self._unlock_stack.set_visible_child_name("setup")

        dialog.connect("response", _on_resp)
        dialog.present(self)

    def _on_successful_unlock(self) -> None:
        # Load database files and migrate if needed
        try:
            from db.migration import migrate_if_needed
            migrate_if_needed()
        except Exception as me:
            logger.error("Migration: failed after manual unlock: %s", me)

        self._load_connections()
        self._hosts_page.refresh()
        self._keychain_page.refresh()
        self._port_forwarding_tab.refresh()
        if hasattr(self._vault_settings_tab, "_check_status"):
            self._vault_settings_tab._check_status()

        self._main_stack.set_visible_child_name("main_ui")
        self._ssh_service.auto_start_forward_rules()

    # ── Connection Editor Dialog ──────────────────────────────

    def show_connection_editor(self, connection: Connection | None = None) -> None:
        """Redirect to the hosts page inline editor."""
        self._on_nav_btn_clicked("hosts")
        self._hosts_page.show_editor(connection)

    # ── Terminal Actions ──────────────────────────────────────

    def _connect_to(self, conn: Connection) -> None:
        """Open an SSH terminal tab for the given connection."""
        try:
            self._terminal_tab_view.open_ssh_tab(
                conn,
                on_os_detected=self._on_os_detected,
            )
            # Notify last_connected
            conn.last_connected = datetime.now(timezone.utc)
            self._db.save_connection(conn)
        except Exception as e:
            self._show_toast(_("Connection error: {e}").format(e=e))

    def _on_os_detected(self, conn_id: str, os_id: str) -> None:
        """Propagate detected OS icon to connection card in hosts grid."""
        logger.info(f"UI: OS detected for {conn_id} -> {os_id}")
        if hasattr(self, "_hosts_page") and self._hosts_page:
            child = self._hosts_page._flow_box.get_first_child()
            while child is not None:
                if getattr(child, "connection", None) and child.connection.id == conn_id:
                    child.connection.os_id = os_id
                    
                    # Targeted replacement of the card header OS icon
                    box = child.get_child()
                    if box and isinstance(box, Gtk.Box):
                        header = box.get_first_child()
                        if header and isinstance(header, Gtk.Box):
                            icon_box = header.get_first_child()
                            if icon_box and isinstance(icon_box, Gtk.Box):
                                while c := icon_box.get_first_child():
                                    icon_box.remove(c)
                                icon_box.append(child._get_os_icon_widget(os_id))
                    break
                child = child.get_next_sibling()

    def _open_local_shell(self) -> None:
        """Open a local shell tab."""
        self._terminal_tab_view.open_local_tab()

    def show_vault_settings(self) -> None:
        """Switch category navigation sidebar to Vault Settings page."""
        self._on_nav_btn_clicked("vault_settings")

    def _open_sftp_for(self, conn: Connection) -> None:
        """Open an SFTP tab for the given connection."""
        self._terminal_tab_view.open_sftp_tab(conn)

    # ── Event Handlers ────────────────────────────────────────

    def _on_tabs_changed(self, tab_view: Adw.TabView, _pspec: Any) -> None:
        """Switch visibility of Terminals sidebar row and stack active child."""
        n_pages = tab_view.get_n_pages()
        terms_row = self._nav_rows.get("terminals")
        if terms_row:
            terms_row.set_visible(n_pages > 0)

        if n_pages == 0:
            # Revert selection to Hosts
            self._on_nav_btn_clicked("hosts")
            self._content_stack.set_visible_child_name("hosts")

            app = self.get_application()
            if app and len(app.get_windows()) > 1:
                self.close()
        else:
            self._on_nav_btn_clicked("terminals")
            self._content_stack.set_visible_child_name("terminals")
            self._update_window_title()

    def _on_selected_page_changed(self, tab_view: Adw.TabView, _pspec: Any) -> None:
        self._update_window_title()

    def _update_window_title(self) -> None:
        # Window titles only make sense when viewing terminal tab
        if self._content_stack.get_visible_child_name() != "terminals":
            return
        
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            child = page.get_child()
            title = page.get_title() or _("Untitled")
            subtitle = ""
            if hasattr(child, "connection") and child.connection:
                subtitle = child.connection.hostname
            self._window_title.set_title(title)
            self._window_title.set_subtitle(subtitle)

    def _on_page_attached(self, tab_view: Adw.TabView, page: Adw.TabPage, position: int) -> None:
        page.connect("notify::title", self._on_page_title_changed)

    def _on_page_title_changed(self, page: Adw.TabPage, _pspec: Any) -> None:
        if self._terminal_tab_view.tab_view.get_selected_page() == page:
            self._update_window_title()

    def _refresh_merge_button_visibility(self) -> bool:
        app = self.get_application()
        if app:
            windows = app.get_windows()
            others = [w for w in windows if w != self and isinstance(w, SentinelWindow)]
            self._merge_btn.set_visible(len(others) > 0)
        return True

    def _merge_all_to_other_window(self) -> None:
        app = self.get_application()
        if not app:
            return

        windows = app.get_windows()
        target_window = None
        for w in windows:
            if w != self and isinstance(w, SentinelWindow):
                target_window = w
                break

        if not target_window:
            return

        source_view = self._terminal_tab_view.tab_view
        target_view = target_window._terminal_tab_view.tab_view

        pages = [source_view.get_nth_page(i) for i in range(source_view.get_n_pages())]
        for page in pages:
            pos = target_view.get_n_pages()
            source_view.transfer_page(page, target_view, pos)

        if target_view.get_n_pages() > 0:
            target_view.set_selected_page(target_view.get_nth_page(target_view.get_n_pages() - 1))

        target_window.present()
        self.close()

    def _on_delete_selected(self, conn: Connection, parent_dialog: Gtk.Widget) -> None:
        dialog = Adw.AlertDialog(
            heading=_('Remove "{name}"?').format(name=conn.name),
            body=_("This connection will be permanently removed."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def _on_response(_d, response):
            if response == "remove":
                self._db.delete_connection(conn.id)
                self._load_connections()
                self._show_toast(_("Removed: {name}").format(name=conn.name))

        dialog.connect("response", _on_response)
        dialog.present(parent_dialog)

    def _on_clear_host_key(self, conn: Connection) -> None:
        logger.info(f"UI: Clearing host key and OS info for {conn.hostname}")
        deleted_count = self._db.delete_known_hosts(conn.hostname, conn.port)

        conn.os_id = None
        self._db.save_connection(conn)
        self._load_connections()

        self._terminal_tab_view.notify_connection_updated(conn)

        if deleted_count > 0:
            self._show_toast(_("Cleared host key and OS info for {hostname}").format(hostname=conn.hostname))
        else:
            self._show_toast(_("Cleared OS info for {hostname}").format(hostname=conn.hostname))

    def refresh_terminal_themes(self) -> None:
        if hasattr(self, "_terminal_tab_view"):
            self._terminal_tab_view.refresh_theme()

    # ── Data ──────────────────────────────────────────────────

    def _load_connections(self) -> None:
        if hasattr(self, "_hosts_page") and self._hosts_page:
            self._hosts_page.refresh()

    # ── Shortcuts ─────────────────────────────────────────────

    def _setup_shortcuts(self) -> None:
        controller = Gtk.ShortcutController.new()
        controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)

        def _wrap(func):
            def callback(*_):
                func()
                return True
            return callback

        shortcuts = [
            ("<Control>t", _wrap(self._open_local_shell)),
            ("<Control>w", _wrap(self._close_current_tab)),
            ("<Control><Shift>c", _wrap(self._copy_terminal)),
            ("<Control><Shift>v", _wrap(self._paste_terminal)),
        ]

        for accel, callback in shortcuts:
            trigger = Gtk.ShortcutTrigger.parse_string(accel)
            action = Gtk.CallbackAction.new(callback)
            controller.add_shortcut(Gtk.Shortcut.new(trigger, action))

        self.add_controller(controller)

    def _close_current_tab(self) -> None:
        self._terminal_tab_view.close_current_tab()

    def _copy_terminal(self) -> None:
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            page.get_child().copy_clipboard()

    def _paste_terminal(self) -> None:
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            page.get_child().paste_clipboard()

    # ── Toast / Dialog Alerts ─────────────────────────────────

    def _show_toast(self, message: str) -> None:
        if hasattr(self, "_toast_overlay") and self._toast_overlay:
            toast = Adw.Toast(title=message)
            toast.set_timeout(3)
            self._toast_overlay.add_toast(toast)

    def _show_unlock_toast(self, message: str) -> None:
        toast = Adw.Toast(title=message)
        toast.set_timeout(3)
        self._unlock_toast_overlay.add_toast(toast)

    # ── Multi-window ──────────────────────────────────────────

    def _create_new_window_for_tab(self, *args) -> Adw.TabView | None:
        app = self.get_application()
        if not app:
            return None
        new_window = SentinelWindow(application=app)
        new_window.present()
        new_window._content_stack.set_visible_child_name("terminals")
        return new_window._terminal_tab_view.tab_view

    # ── Cleanup ───────────────────────────────────────────────

    def do_close_request(self) -> bool:
        self._db.close()
        return False
