# SPDX-License-Identifier: GPL-3.0-or-later

"""Main application window — sidebar + terminal split view."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from db.database import Database
from models.connection import AuthMethod, Connection, ValidationError
from services.ssh_service import SSHService
from views.connection_list import ConnectionListSidebar
from views.terminal_view import TerminalTabView


class SentinelWindow(Adw.ApplicationWindow):
    """Main window with responsive split view and terminal tabs."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        super().__init__(
            default_width=1100,
            default_height=700,
            title="Sentinel",
            **kwargs,
        )

        # Core services
        self._db = Database()
        self._db.open()
        self._ssh_service = SSHService()

        # Build UI
        self._build_ui()
        self._load_connections()
        self._setup_shortcuts()

    # ── UI Construction ───────────────────────────────────────

    def _build_ui(self) -> None:
        # Toast overlay wraps everything
        self._toast_overlay = Adw.ToastOverlay()

        # Split view: sidebar + content
        self._split_view = Adw.NavigationSplitView()
        self._split_view.set_min_sidebar_width(260)
        self._split_view.set_max_sidebar_width(380)

        # ─── Sidebar ─────────────────────────────────────────
        sidebar_page = Adw.NavigationPage(title="Connections")
        sidebar_toolbar = Adw.ToolbarView()

        sidebar_header = Adw.HeaderBar()
        sidebar_header.set_show_title(True)

        add_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="New Connection  (Ctrl+N)")
        add_btn.connect("clicked", lambda _: self.show_connection_editor())
        sidebar_header.pack_start(add_btn)

        # Menu
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", tooltip_text="Menu")
        menu_model = Gio.Menu()
        menu_model.append("Vault Settings", "app.vault_settings")
        menu_model.append("About Sentinel", "app.about")
        menu_model.append("Quit", "app.quit")
        menu_btn.set_menu_model(menu_model)
        sidebar_header.pack_end(menu_btn)

        sidebar_toolbar.add_top_bar(sidebar_header)

        # Search
        self._search_entry = Gtk.SearchEntry(placeholder_text="Search connections…")
        self._search_entry.set_margin_start(8)
        self._search_entry.set_margin_end(8)
        self._search_entry.set_margin_top(4)
        self._search_entry.set_margin_bottom(4)
        self._search_entry.connect("search-changed", self._on_search_changed)

        search_clamp = Adw.Clamp(maximum_size=400)
        search_clamp.set_child(self._search_entry)

        # Connection list
        self._sidebar = ConnectionListSidebar()
        self._sidebar.connect_activated(self._on_connection_activated)
        self._sidebar.connect_sftp_clicked(self._open_sftp_for)
        self._sidebar.connect_edit_clicked(self.show_connection_editor)
        self._sidebar.connect_clear_host_key_clicked(self._on_clear_host_key)

        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar_box.append(search_clamp)

        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        sep.set_margin_top(4)
        sep.set_margin_bottom(4)
        sidebar_box.append(sep)

        sidebar_box.append(self._sidebar.widget)

        sidebar_toolbar.set_content(sidebar_box)
        sidebar_page.set_child(sidebar_toolbar)

        # ─── Content area ────────────────────────────────────
        content_page = Adw.NavigationPage(title="Sentinel")
        content_toolbar = Adw.ToolbarView()

        # Content stack: welcome page OR terminal area
        self._content_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=200,
        )

        # Welcome page
        welcome = self._build_welcome_page()
        self._content_stack.add_named(welcome, "welcome")

        # Terminal tab area
        self._terminal_tab_view = TerminalTabView(self._ssh_service)
        self._content_stack.add_named(self._terminal_tab_view.widget, "terminal")

        # ─── Highly Stable Native Header Bar + Tab Bar ───
        content_header = Adw.HeaderBar()
        
        # Give the window a nice dynamic title
        self._window_title = Adw.WindowTitle(title="Terminal", subtitle="")
        content_header.set_title_widget(self._window_title)

        # Utilize native Adw.TabBar for bulletproof window drag, tab drag, & tear-offs
        self._tab_bar = Adw.TabBar()
        self._tab_bar.set_view(self._terminal_tab_view.tab_view)
        
        # Give tab bar empty state styling
        self._tab_bar.set_autohide(False)  # Always visible, even with 0 tabs
        self._tab_bar.set_expand_tabs(True) # Make last tab draggable by making it fill space
        
        # Connect tab drop-out to create new window
        self._terminal_tab_view.tab_view.connect("create-window", self._create_new_window_for_tab)

        # Local Shell Button (back to HeaderBar)
        shell_btn = Gtk.Button(
            icon_name="computer-symbolic",
            tooltip_text="Open Local Shell (Ctrl+T)"
        )
        shell_btn.add_css_class("flat")
        shell_btn.set_valign(Gtk.Align.CENTER)
        shell_btn.connect("clicked", lambda _: self._open_local_shell())
        content_header.pack_end(shell_btn)

        # "Merge All" button for TabBar (for secondary windows)
        self._merge_btn = Gtk.Button(
            icon_name="list-remove-symbolic",
            tooltip_text="Merge all tabs into another window and close"
        )
        self._merge_btn.add_css_class("flat")
        self._merge_btn.set_valign(Gtk.Align.CENTER)
        self._merge_btn.connect("clicked", lambda _: self._merge_all_to_other_window())
        self._tab_bar.set_end_action_widget(self._merge_btn)

        # Add both to the toolbar view as independent top bars!
        content_toolbar.add_top_bar(content_header)
        content_toolbar.add_top_bar(self._tab_bar)

        # Connect tab title/selection listener to update HeaderBar window title
        self._terminal_tab_view.tab_view.connect("notify::selected-page", self._on_selected_page_changed)
        self._terminal_tab_view.tab_view.connect("page-attached", self._on_page_attached)

        # Connect tab count listener to handle switching back to welcome page
        self._terminal_tab_view.tab_view.connect("notify::n-pages", self._on_tabs_changed)
        
        # Periodically refresh the Merge button visibility
        GLib.timeout_add(1000, self._refresh_merge_button_visibility)

        self._content_stack.set_visible_child_name("welcome")
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
        self.set_content(self._toast_overlay)

    def _build_welcome_page(self) -> Gtk.Widget:
        """Build the welcome / empty-state page."""
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            vexpand=True,
        )

        icon = Gtk.Image.new_from_icon_name("utilities-terminal-symbolic")
        icon.set_pixel_size(96)
        icon.add_css_class("welcome-icon")
        box.append(icon)

        title = Gtk.Label(label="Sentinel")
        title.add_css_class("welcome-title")
        box.append(title)

        subtitle = Gtk.Label(label="Secure SSH Connection Manager")
        subtitle.add_css_class("welcome-subtitle")
        box.append(subtitle)

        btn_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            margin_top=24,
        )

        add_btn = Gtk.Button(label="New Connection")
        add_btn.add_css_class("suggested-action")
        add_btn.add_css_class("pill")
        add_btn.connect("clicked", lambda _: self.show_connection_editor())
        btn_box.append(add_btn)

        shell_btn = Gtk.Button(label="Local Shell")
        shell_btn.add_css_class("pill")
        shell_btn.connect("clicked", lambda _: self._open_local_shell())
        btn_box.append(shell_btn)

        box.append(btn_box)

        # Keyboard hints
        hints = Gtk.Label(
            label="Ctrl+N  New Connection  ·  Ctrl+T  Local Shell  ·  Ctrl+F  Search",
        )
        hints.add_css_class("dim-label")
        hints.add_css_class("caption")
        hints.set_margin_top(32)
        box.append(hints)

        return box

    # ── Connection Editor Dialog ──────────────────────────────

    def show_connection_editor(self, connection: Connection | None = None) -> None:
        """Open the connection editor dialog."""
        is_edit = connection is not None
        dialog = Adw.Dialog()
        dialog.set_title("Edit Connection" if is_edit else "New Connection")
        dialog.set_content_width(480)
        dialog.set_content_height(520)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _: dialog.close())
        header.pack_start(cancel_btn)

        save_btn = Gtk.Button(label="Save")
        save_btn.add_css_class("suggested-action")
        header.pack_end(save_btn)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        form_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        # ─── Basic group ───
        basic_group = Adw.PreferencesGroup(title="Basic")
        basic_group.add_css_class("editor-page")

        name_row = Adw.EntryRow(title="Name")
        if connection:
            name_row.set_text(connection.name)
        basic_group.add(name_row)

        host_row = Adw.EntryRow(title="Hostname")
        if connection:
            host_row.set_text(connection.hostname)
        basic_group.add(host_row)

        port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        port_row.set_title("Port")
        port_row.set_value(connection.port if connection else 22)
        basic_group.add(port_row)

        user_row = Adw.EntryRow(title="Username")
        if connection:
            user_row.set_text(connection.username)
        basic_group.add(user_row)

        form_box.append(basic_group)

        # ─── Auth group ───
        auth_group = Adw.PreferencesGroup(title="Authentication")
        auth_group.add_css_class("editor-page")

        auth_items = Gtk.StringList.new(
            ["SSH Key", "Password", "Key + Passphrase", "SSH Agent", "Vault"]
        )
        auth_row = Adw.ComboRow(title="Method", model=auth_items)
        auth_map = {
            AuthMethod.KEY: 0, AuthMethod.PASSWORD: 1,
            AuthMethod.KEY_PASSPHRASE: 2, AuthMethod.AGENT: 3, AuthMethod.VAULT: 4,
        }
        reverse_auth_map = {v: k for k, v in auth_map.items()}
        if connection:
            auth_row.set_selected(auth_map.get(connection.auth_method, 0))
        auth_group.add(auth_row)

        key_row = Adw.EntryRow(title="Key File Path (optional)")
        if connection and connection.key_path:
            key_row.set_text(connection.key_path)
        auth_group.add(key_row)

        def _on_auth_changed(*_args) -> None:  # noqa: ANN002
            method = reverse_auth_map.get(auth_row.get_selected(), AuthMethod.KEY)
            key_row.set_visible(method in (AuthMethod.KEY, AuthMethod.KEY_PASSPHRASE))
            vault_row.set_visible(method == AuthMethod.VAULT)

        auth_row.connect("notify::selected", _on_auth_changed)
        
        # Vault SSH Key selection row (read-only display + Select button)
        # vault_item_id is stored in a mutable container so closure can update it
        _vault_sel: list[str | None] = [connection.vault_item_id if connection else None]

        def _vault_sel_id() -> str | None:
            return _vault_sel[0]

        vault_row = Adw.ActionRow(title="SSH Key from Vault")
        vault_row.set_subtitle("Select the vault item that stores the SSH private key")

        vault_label = Gtk.Label()
        vault_label.set_valign(Gtk.Align.CENTER)
        vault_label.add_css_class("dim-label")
        vault_label.add_css_class("caption")
        if connection and connection.vault_item_id:
            vault_label.set_label(connection.vault_item_id[:20] + "…" if len(connection.vault_item_id or "") > 20 else connection.vault_item_id or "Not selected")
        else:
            vault_label.set_label("Not selected")

        vault_clear_btn = Gtk.Button(icon_name="edit-clear-symbolic")
        vault_clear_btn.set_tooltip_text("Clear vault key selection")
        vault_clear_btn.set_valign(Gtk.Align.CENTER)
        vault_clear_btn.add_css_class("flat")
        vault_clear_btn.add_css_class("circular")

        vault_browse_btn = Gtk.Button(label="Select…")
        vault_browse_btn.set_tooltip_text("Select SSH key from Vault")
        vault_browse_btn.set_valign(Gtk.Align.CENTER)
        vault_browse_btn.add_css_class("flat")

        vault_suffix_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        vault_suffix_box.append(vault_label)
        vault_suffix_box.append(vault_clear_btn)
        vault_suffix_box.append(vault_browse_btn)
        vault_row.add_suffix(vault_suffix_box)
        auth_group.add(vault_row)

        def _update_vault_label(item_id: str | None, name: str = "") -> None:
            _vault_sel[0] = item_id
            if item_id:
                display = name if name else (item_id[:18] + "…" if len(item_id) > 18 else item_id)
                vault_label.set_label(display)
            else:
                vault_label.set_label("Not selected")

        def _on_vault_clear(_btn) -> None:
            _update_vault_label(None)

        vault_clear_btn.connect("clicked", _on_vault_clear)

        def _on_browse_vault(_btn) -> None:
            """Open vault key picker — prompt for unlock if needed."""
            from services.vault_service import VaultService
            from gi.repository import GLib as _GLib
            from views.dialogs import prompt_vault_key_selection

            vault = VaultService.get().get_backend("bitwarden")
            if not vault or not vault.is_available:
                self._show_toast("Bitwarden CLI not found. Install it first.")
                return

            # Show dialog immediately in loading state
            def _on_picked(item_id: str | None, item_name: str) -> None:
                if item_id:
                    _update_vault_label(item_id, item_name)
                self._vault_picker = None

            picker = prompt_vault_key_selection(self, None, _on_picked)
            self._vault_picker = picker

            async def _fetch_and_update():
                is_unlocked = await vault.is_unlocked()
                if not is_unlocked:
                    def _notify_locked():
                        picker.destroy()
                        self._show_toast("Please log in / unlock Bitwarden via Vault Settings first.")
                        self.get_application().lookup_action("vault_settings").activate(None)
                        return False
                    _GLib.idle_add(_notify_locked)
                    return

                try:
                    items = await vault.search_credentials("", None)
                    _GLib.idle_add(lambda: picker.set_items(items) and False)
                except Exception as fetch_err:
                    def _on_error():
                        picker.destroy()
                        self._show_toast(f"Failed to fetch vault items: {fetch_err}")
                        return False
                    _GLib.idle_add(_on_error)

            from services.ssh_service import SSHService
            SSHService().engine.run_coroutine(_fetch_and_update())

        vault_browse_btn.connect("clicked", _on_browse_vault)

        _on_auth_changed()  # Init visibility

        form_box.append(auth_group)

        # ─── Notes group ───
        notes_group = Adw.PreferencesGroup(title="Notes")
        notes_group.add_css_class("editor-page")
        notes_row = Adw.EntryRow(title="Notes")
        if connection:
            notes_row.set_text(connection.notes)
        notes_group.add(notes_row)
        form_box.append(notes_group)

        # Error label
        error_bar = Gtk.Label(label="")
        error_bar.add_css_class("error")
        error_bar.set_margin_start(12)
        error_bar.set_margin_end(12)
        error_bar.set_margin_top(8)
        error_bar.set_visible(False)
        form_box.append(error_bar)

        if is_edit and connection:
            delete_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, halign=Gtk.Align.CENTER)
            delete_btn = Gtk.Button(label="Delete Connection")
            delete_btn.add_css_class("destructive-action")
            delete_btn.set_margin_top(24)
            delete_btn.set_margin_bottom(24)
            delete_btn.connect("clicked", lambda _: self._on_delete_selected(connection, dialog))
            delete_box.append(delete_btn)
            form_box.append(delete_box)

        scroll.set_child(form_box)
        toolbar.set_content(scroll)
        dialog.set_child(toolbar)

        def on_save(_btn: Gtk.Button) -> None:
            auth_method = reverse_auth_map.get(auth_row.get_selected(), AuthMethod.KEY)
            if is_edit and connection:
                conn = connection
                conn.name = name_row.get_text()
                conn.hostname = host_row.get_text()
                conn.port = int(port_row.get_value())
                conn.username = user_row.get_text()
                conn.auth_method = auth_method
                conn.key_path = key_row.get_text() or None
                conn.vault_item_id = _vault_sel_id()
                conn.notes = notes_row.get_text()
            else:
                conn = Connection(
                    name=name_row.get_text(),
                    hostname=host_row.get_text(),
                    port=int(port_row.get_value()),
                    username=user_row.get_text(),
                    auth_method=auth_method,
                    key_path=key_row.get_text() or None,
                    vault_item_id=_vault_sel_id(),
                    notes=notes_row.get_text(),
                )

            try:
                self._db.save_connection(conn)
            except ValidationError as e:
                error_bar.set_label(str(e))
                error_bar.set_visible(True)
                return

            self._load_connections()
            dialog.close()
            self._show_toast(f"{'Updated' if is_edit else 'Added'}: {conn.name}")

        save_btn.connect("clicked", on_save)

        # Enter to save in name/host fields
        for row in (name_row, host_row, user_row):
            row.connect("entry-activated", on_save)

        dialog.present(self)

    # ── Terminal Actions ──────────────────────────────────────

    def _connect_to(self, conn: Connection) -> None:
        """Open an SSH terminal tab for the given connection."""
        try:
            self._terminal_tab_view.open_ssh_tab(
                conn,
                on_os_detected=self._sidebar.refresh_os_icon,
            )
            self._content_stack.set_visible_child_name("terminal")
            # Update last_connected
            from datetime import datetime, timezone
            conn.last_connected = datetime.now(timezone.utc)
            self._db.save_connection(conn)
        except Exception as e:
            self._show_toast(f"Connection error: {e}")

    def _open_local_shell(self) -> None:
        """Open a local shell tab."""
        self._terminal_tab_view.open_local_tab()
        self._content_stack.set_visible_child_name("terminal")

    def _open_sftp_for(self, conn: Connection) -> None:
        """Open an SFTP tab for the given connection."""
        self._terminal_tab_view.open_sftp_tab(conn)
        self._content_stack.set_visible_child_name("terminal")

    # ── Event Handlers ────────────────────────────────────────

    def _on_connection_activated(self, connection: Connection) -> None:
        """Single-click / Enter on a connection — open terminal."""
        self._connect_to(connection)

    def _on_tabs_changed(self, tab_view: Adw.TabView, _pspec: Any) -> None:
        """Switch back to welcome page when all tabs are closed."""
        n_pages = tab_view.get_n_pages()
        if n_pages == 0:
            self._content_stack.set_visible_child_name("welcome")
            self._window_title.set_title("Welcome")
            self._window_title.set_subtitle("")
            
            # If this is not the only window, close it automatically when it becomes empty
            app = self.get_application()
            if app and len(app.get_windows()) > 1:
                self.close()
        else:
            self._content_stack.set_visible_child_name("terminal")
            self._update_window_title()

    def _on_selected_page_changed(self, tab_view: Adw.TabView, _pspec: Any) -> None:
        """Update window title when selected tab changes."""
        self._update_window_title()

    def _update_window_title(self) -> None:
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            child = page.get_child()
            
            # Simple title extraction based on what the page holds
            title = page.get_title()
            subtitle = ""
            
            if hasattr(child, "connection") and child.connection:
                subtitle = child.connection.hostname
                
            self._window_title.set_title(title)
            self._window_title.set_subtitle(subtitle)

    def _on_page_attached(self, tab_view: Adw.TabView, page: Adw.TabPage, position: int) -> None:
        """When a page is attached, listen to its title changes."""
        page.connect("notify::title", self._on_page_title_changed)

    def _on_page_title_changed(self, page: Adw.TabPage, _pspec: Any) -> None:
        """Update window title if the active page changes its title."""
        if self._terminal_tab_view.tab_view.get_selected_page() == page:
            self._update_window_title()

    def _refresh_merge_button_visibility(self) -> bool:
        """Show the merge button ONLY if there are other windows to merge into."""
        app = self.get_application()
        if app:
            windows = app.get_windows()
            # Only show if there's at least one other window which is also a SentinelWindow
            others = [w for w in windows if w != self and isinstance(w, SentinelWindow)]
            self._merge_btn.set_visible(len(others) > 0)
        return True

    def _merge_all_to_other_window(self) -> None:
        """Transfer all pages from this window to another window and then close this one."""
        app = self.get_application()
        if not app:
            return
            
        windows = app.get_windows()
        # Find the first OTHER window
        target_window = None
        for w in windows:
            if w != self and isinstance(w, SentinelWindow):
                target_window = w
                break
                
        if not target_window:
            return
            
        # Transfer all pages
        source_view = self._terminal_tab_view.tab_view
        target_view = target_window._terminal_tab_view.tab_view
        
        # We need to collect them first because transferring will change n_pages
        pages = [source_view.get_nth_page(i) for i in range(source_view.get_n_pages())]
        
        for page in pages:
            # position must be >= 0 in Python Gtk bindings
            pos = target_view.get_n_pages()
            source_view.transfer_page(page, target_view, pos)
            
        # Select the last transferred page in target window
        if target_view.get_n_pages() > 0:
            target_view.set_selected_page(target_view.get_nth_page(target_view.get_n_pages() - 1))
            
        target_window.present()
        self.close()

    def _on_delete_selected(self, conn: Connection, parent_dialog: Adw.Dialog) -> None:
        dialog = Adw.AlertDialog(
            heading=f'Delete "{conn.name}"?',
            body="This connection will be permanently removed.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        
        def _on_response(_d, response):
            if response == "delete":
                self._db.delete_connection(conn.id)
                self._load_connections()
                self._show_toast(f"Deleted: {conn.name}")
                parent_dialog.close()
                self._content_stack.set_visible_child_name(
                    "terminal" if self._terminal_tab_view.has_tabs else "welcome"
                )
                
        dialog.connect("response", _on_response)
        dialog.present(parent_dialog)

    def _on_clear_host_key(self, conn: Connection) -> None:
        """Clear the host key from the database."""
        deleted_count = self._db.delete_known_hosts(conn.hostname, conn.port)
        if deleted_count > 0:
            self._show_toast(f"Cleared host key for {conn.hostname}")
        else:
            self._show_toast(f"No saved host keys found for {conn.hostname}")

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        query = entry.get_text().strip()
        connections = (
            self._db.search_connections(query) if query
            else self._db.list_connections()
        )
        self._sidebar.set_connections(connections)

    # ── Data ──────────────────────────────────────────────────

    def _load_connections(self) -> None:
        self._sidebar.set_connections(self._db.list_connections())

    # ── Shortcuts ─────────────────────────────────────────────

    def _setup_shortcuts(self) -> None:
        controller = Gtk.ShortcutController()

        shortcuts = [
            ("<primary>f", self._focus_search),
            ("<primary>t", lambda *_: (self._open_local_shell(), True)[1]),
            ("<primary>w", lambda *_: (self._close_current_tab(), True)[1]),
            ("<primary><shift>c", lambda *_: (self._copy_terminal(), True)[1]),
            ("<primary><shift>v", lambda *_: (self._paste_terminal(), True)[1]),
        ]

        for accel, callback in shortcuts:
            controller.add_shortcut(
                Gtk.Shortcut(
                    trigger=Gtk.ShortcutTrigger.parse_string(accel),
                    action=Gtk.CallbackAction.new(callback),
                )
            )

        self.add_controller(controller)

    def _focus_search(self, *_args) -> bool:  # noqa: ANN002
        self._search_entry.grab_focus()
        return True

    def _close_current_tab(self) -> None:
        self._terminal_tab_view.close_current_tab()
        if not self._terminal_tab_view.has_tabs:
            self._content_stack.set_visible_child_name("welcome")

    def _copy_terminal(self) -> None:
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            page.get_child().copy_clipboard()

    def _paste_terminal(self) -> None:
        page = self._terminal_tab_view.tab_view.get_selected_page()
        if page:
            page.get_child().paste_clipboard()

    # ── Toast ─────────────────────────────────────────────────

    def _show_toast(self, message: str) -> None:
        toast = Adw.Toast(title=message)
        toast.set_timeout(3)
        self._toast_overlay.add_toast(toast)

    # ── Multi-window ──────────────────────────────────────────

    def _create_new_window_for_tab(self, *args) -> Adw.TabView | None:
        """Create a new window, presenting it, and return its Adw.TabView.
        Used for tearing off a tab into a new window.
        """
        app = self.get_application()
        if not app:
            return None
        new_window = SentinelWindow(application=app)
        new_window.present()
        # Pre-select terminal stack page, as it will get the tab
        new_window._content_stack.set_visible_child_name("terminal")
        return new_window._terminal_tab_view.tab_view

    # ── Cleanup ───────────────────────────────────────────────

    def do_close_request(self) -> bool:
        self._db.close()
        return False
