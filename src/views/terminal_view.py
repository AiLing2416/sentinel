# SPDX-License-Identifier: GPL-3.0-or-later

"""VTE terminal view — embeddable terminal widget for SSH sessions."""

from __future__ import annotations

import logging
from typing import Callable, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Vte", "3.91")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango, Vte  # noqa: E402

from models.connection import Connection
from services.ssh_service import SSHService

logger = logging.getLogger(__name__)


class TerminalTab(Gtk.Box):
    """A single terminal tab containing a VTE terminal + status bar."""

    def __init__(
        self,
        connection: Connection | None,
        ssh_command: Any | None, # LocalCommand or None
        ssh_service: SSHService,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self._connection = connection
        self._ssh_command = ssh_command
        self._ssh_service = ssh_service
        self._on_close = on_close
        self._on_os_detected: Callable[[str, str], None] | None = None
        
        # State
        self._child_pid: int | None = None
        self._session_bridge: Any | None = None
        self._bg_task: Any = None
        self.is_remote = self._connection is not None
        
        self._build_ui()
        
        if self.is_remote:
            self._connect_remote()
        else:
            self._spawn_local()

    @property
    def connection(self) -> Connection | None:
        return self._connection

    @property
    def title(self) -> str:
        if self._connection:
            return f"{self._connection.username}@{self._connection.hostname}" if self._connection.username else self._connection.hostname
        return "Local Shell"

    @property
    def is_running(self) -> bool:
        if self.is_remote:
            return self._session_bridge is not None
        return self._child_pid is not None

    def request_close(self) -> None:
        """Ask the parent to close this tab."""
        if self._on_close:
            self._on_close()

    # ── UI ────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Terminal widget
        self._terminal = Vte.Terminal()
        self._terminal.set_vexpand(True)
        self._terminal.set_hexpand(True)

        # Terminal appearance
        self._terminal.set_scroll_on_output(True)
        self._terminal.set_scroll_on_keystroke(True)
        self._terminal.set_scrollback_lines(10000)
        self._terminal.set_mouse_autohide(True)

        # Font
        font_desc = Pango.FontDescription.from_string("Monospace 11")
        self._terminal.set_font(font_desc)
        self._terminal.set_cursor_blink_mode(Vte.CursorBlinkMode.ON)
        self._terminal.set_cursor_shape(Vte.CursorShape.BLOCK)
        
        self._apply_theme()
        self._terminal.set_allow_hyperlink(True)

        # Signals
        if self.is_remote:
            self._terminal_commit_sid = self._terminal.connect("commit", self._on_vte_commit)
            self._terminal.connect("notify::columns", self._on_vte_resize)
            self._terminal.connect("notify::rows", self._on_vte_resize)
        else:
            self._terminal.connect("child-exited", self._on_local_child_exited)
            
        self._terminal.connect("window-title-changed", self._on_title_changed)

        # Key controller for copy/paste
        key_ctrl = Gtk.EventControllerKey.new()
        key_ctrl.connect("key-pressed", self._on_terminal_key_pressed)
        self._terminal.add_controller(key_ctrl)

        # Auto-copy on selection
        self._terminal.connect("selection-changed", self._on_selection_changed)

        # Right-click to paste
        click_gesture = Gtk.GestureClick.new()
        click_gesture.set_button(Gdk.BUTTON_SECONDARY)
        click_gesture.connect("pressed", self._on_terminal_right_click)
        self._terminal.add_controller(click_gesture)

        # Scrolled container
        scroll = Gtk.ScrolledWindow(vexpand=True, hexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroll.set_child(self._terminal)
        self.append(scroll)

        # Status bar
        self._status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._status_bar.add_css_class("toolbar")

        self._status_label = Gtk.Label(
            label=f"Connecting to {self.title}…" if self.is_remote else "Spawning local shell...",
            xalign=0,
            hexpand=True,
            ellipsize=3,
        )
        self._status_label.add_css_class("dim-label")
        self._status_label.add_css_class("caption")
        self._status_bar.append(self._status_label)
        self.append(self._status_bar)

    def _apply_theme(self) -> None:
        bg = Gdk.RGBA()
        bg.parse("#1e1e2e")
        fg = Gdk.RGBA()
        fg.parse("#cdd6f4")
        hex_colors = [
            "#45475a", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de",
            "#585b70", "#f38ba8", "#a6e3a1", "#f9e2af", "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8"
        ]
        palette = []
        for h in hex_colors:
            c = Gdk.RGBA()
            c.parse(h)
            palette.append(c)
        self._terminal.set_colors(fg, bg, palette)

    # ── Remote Process ─────────────────────────────────────────

    def _connect_remote(self) -> None:
        from views.dialogs import prompt_password, prompt_host_key, prompt_vault_unlock, prompt_vault_item_selection
        from services.vault_service import VaultService
        
        def _ask_password(conn, resolve):
            prompt_password(self.get_root(), f"Password for {conn.hostname}", f"{conn.username}@{conn.hostname}", resolve)
            
        def _ask_passphrase(key_path, resolve):
            prompt_password(self.get_root(), "Unlock SSH Key", f"Enter passphrase for {key_path}", resolve)
            
        def _ask_host_key(hostname, fingerprint, alg, resolve):
            prompt_host_key(self.get_root(), hostname, fingerprint, alg, resolve)

        def _ask_vault_unlock(vault_name, resolve):
            # We need to bridge to UI, but this is a callback in GTK thread
            # VaultService.unlock needs to be called.
            def _on_password(password):
                if password:
                    # We run the unlock in the background thread
                    async def do_unlock():
                        success = await VaultService.get().active_backend.unlock(password)
                        resolve(success)
                    self._ssh_service.engine.run_coroutine(do_unlock())
                else:
                    resolve(False)
            prompt_vault_unlock(self.get_root(), vault_name, _on_password)

        def _ask_vault_item(items, resolve):
            prompt_vault_item_selection(self.get_root(), items, resolve)

        callbacks = {
            "ask_password": _ask_password,
            "ask_passphrase": _ask_passphrase,
            "ask_host_key": _ask_host_key,
            "ask_vault_unlock": _ask_vault_unlock,
            "ask_vault_item": _ask_vault_item,
            "on_connected": self._on_remote_connected,
            "on_error": self._on_remote_error,
            "on_disconnected": self._on_remote_disconnected,
            "on_cancelled": self.request_close,
        }
        if self._on_os_detected:
            callbacks["on_os_detected"] = self._on_os_detected

        coro = self._ssh_service.connect_and_start_session(
            self._connection,
            callbacks,
            self._on_remote_output,
            self._on_remote_exited,
            status_cb=self._status_label.set_label
        )
        self._bg_task = self._ssh_service.engine.run_coroutine(coro)

    def _on_remote_connected(self, bridge: Any) -> None:
        self._session_bridge = bridge
        self._status_label.set_label(f"Connected — {self.title}")
        cols, rows = self._terminal.get_column_count(), self._terminal.get_row_count()
        bridge.resize(cols, rows)

    def _on_remote_error(self, msg: str) -> None:
        self._status_label.set_label(msg)
        self._print_terminal_error(msg)
        self._show_reconnect_prompt()
        
    def _on_remote_disconnected(self, exc: Exception | None) -> None:
        self._status_label.set_label(f"Disconnected: {exc}" if exc else "Disconnected")
        self._session_bridge = None
        self._show_reconnect_prompt()
        
    def _on_remote_output(self, data: bytes) -> None:
        self._terminal.feed(data)
        
    def _on_vte_commit(self, terminal: Vte.Terminal, text: str, size: int) -> None:
        if self._session_bridge:
            self._session_bridge.write(text.encode("utf-8"))
            
    def _on_vte_resize(self, terminal: Vte.Terminal, param_spec: Any) -> None:
        if self._session_bridge:
            cols, rows = terminal.get_column_count(), terminal.get_row_count()
            self._session_bridge.resize(cols, rows)

    def _on_remote_exited(self, exit_status: int) -> None:
        self._status_label.set_label(f"Exited with code {exit_status}")
        self._session_bridge = None
        self._show_reconnect_prompt()

    # ── Local Process ──────────────────────────────────────────

    def _spawn_local(self) -> None:
        argv = self._ssh_command.argv if self._ssh_command else ["/bin/bash"]
        env = list(GLib.get_environ())
        
        self._terminal.spawn_async(
            Vte.PtyFlags.DEFAULT,
            None, argv, env,
            GLib.SpawnFlags.DEFAULT,
            None, None, -1, None,
            self._on_local_spawn_complete,
        )

    def _on_local_spawn_complete(self, terminal: Vte.Terminal, pid: int, error: GLib.Error | None) -> None:
        if error:
            self._status_label.set_label(f"Error: {error.message}")
            return
        self._child_pid = pid
        self._status_label.set_label("Local Shell")

    def _on_local_child_exited(self, terminal: Vte.Terminal, exit_status: int) -> None:
        self._child_pid = None
        self._status_label.set_label(f"Exited code {exit_status >> 8}")
        self._show_reconnect_prompt()

    # ── Shared ────────────────────────────────────────────────

    def _print_terminal_error(self, msg: str) -> None:
        self._terminal.feed(f"\r\n\033[1;31m{msg}\033[0m\r\n".encode("utf-8"))
        
    def _show_reconnect_prompt(self) -> None:
        self._terminal.feed(b"\r\n\033[1;33m[Session ended. Press Enter to reconnect, or Ctrl+D to close this tab.]\033[0m\r\n")
        self._reconnect_sid = self._terminal.connect("commit", self._on_reconnect_key)

    def _on_reconnect_key(self, terminal: Vte.Terminal, text: str, size: int) -> None:
        if "\x04" in text:
            terminal.disconnect(self._reconnect_sid)
            self.request_close()
        elif "\r" in text or "\n" in text:
            terminal.disconnect(self._reconnect_sid)
            self._status_label.set_label(f"Reconnecting…")
            self._terminal.reset(True, True)
            if self.is_remote:
                self._connect_remote()
            else:
                self._spawn_local()

    def _on_title_changed(self, terminal: Vte.Terminal) -> None:
        pass

    def _on_selection_changed(self, terminal: Vte.Terminal) -> None:
        if terminal.get_has_selection():
            terminal.copy_clipboard_format(Vte.Format.TEXT)

    def _on_terminal_right_click(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        self._terminal.paste_clipboard()
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)

    def _on_terminal_key_pressed(self, controller: Gtk.EventControllerKey, keyval: int, keycode: int, state: Gdk.ModifierType) -> bool:
        # Check for Ctrl+Shift+C
        if keyval in (Gdk.KEY_C, Gdk.KEY_c) and (state & Gdk.ModifierType.CONTROL_MASK) and (state & Gdk.ModifierType.SHIFT_MASK):
            self._terminal.copy_clipboard_format(Vte.Format.TEXT)
            return True
        # Check for Ctrl+Shift+V
        if keyval in (Gdk.KEY_V, Gdk.KEY_v) and (state & Gdk.ModifierType.CONTROL_MASK) and (state & Gdk.ModifierType.SHIFT_MASK):
            self._terminal.paste_clipboard()
            return True
        return False

    def copy_clipboard(self) -> None:
        self._terminal.copy_clipboard_format(Vte.Format.TEXT)

    def paste_clipboard(self) -> None:
        self._terminal.paste_clipboard()

    def grab_focus(self) -> bool:  # type: ignore[override]
        return self._terminal.grab_focus()

    def terminate(self) -> None:
        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()
            
        if self._child_pid is not None:
            import signal, os
            try:
                os.kill(self._child_pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            self._child_pid = None
        if self._session_bridge:
            self._session_bridge.close()
            self._session_bridge = None


class TerminalTabView:
    """Manages multiple terminal tabs using Adw.TabView + TabBar."""

    def __init__(self, ssh_service: SSHService) -> None:
        self._ssh_service = ssh_service
        self._tabs: dict[str, Adw.TabPage] = {}  # connection_id -> TabPage

        self._build_ui()

    def _build_ui(self) -> None:
        self._root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Tab view (page management — visual tab strip is handled by ChromeTabBar)
        self._tab_view = Adw.TabView()
        self._tab_view.connect("close-page", self._on_close_page)
        self._tab_view.connect("notify::selected-page", self._on_page_selected)

        # Tab overview (for mobile / many tabs)
        self._tab_overview = Adw.TabOverview()
        self._tab_overview.set_view(self._tab_view)
        self._tab_overview.set_enable_new_tab(True)
        self._tab_overview.connect("create-tab", self._on_create_local_tab)

        # Hook up signals for cross-window drag & drop
        self._tab_view.connect("page-attached", self._on_page_attached)
        self._tab_view.connect("page-detached", self._on_page_detached)

        self._root.append(self._tab_view)

    @property
    def widget(self) -> Gtk.Widget:
        return self._root

    @property
    def tab_view(self) -> Adw.TabView:
        return self._tab_view

    @property
    def has_tabs(self) -> bool:
        return self._tab_view.get_n_pages() > 0
    def open_ssh_tab(self, connection: Connection, on_os_detected: Callable | None = None) -> TerminalTab:
        """Open an SSH terminal tab for a connection."""
        terminal_tab = TerminalTab(
            connection=connection,
            ssh_command=None,
            ssh_service=self._ssh_service,
        )
        terminal_tab._on_os_detected = on_os_detected

        page = self._tab_view.append(terminal_tab)
        terminal_tab._on_close = lambda t=terminal_tab: self._close_specific_tab_by_widget(t)
        
        page.set_title(terminal_tab.title)
        page.set_icon(Gio.ThemedIcon.new("utilities-terminal-symbolic"))
        page.set_live_thumbnail(True)

        self._tabs[connection.id] = page
        self._tab_view.set_selected_page(page)

        GLib.idle_add(lambda: terminal_tab.grab_focus() and False)
        return terminal_tab

    def open_local_tab(self) -> TerminalTab:
        """Open a local shell tab."""
        ssh_cmd = self._ssh_service.build_local_shell_command()
        terminal_tab = TerminalTab(
            connection=None,
            ssh_command=ssh_cmd,
            ssh_service=self._ssh_service,
        )

        page = self._tab_view.append(terminal_tab)
        terminal_tab._on_close = lambda t=terminal_tab: self._close_specific_tab_by_widget(t)
        
        page.set_title("Local Shell")
        page.set_icon(Gio.ThemedIcon.new("computer-symbolic"))

        self._tab_view.set_selected_page(page)
        GLib.idle_add(lambda: terminal_tab.grab_focus() and False)

        return terminal_tab

    def open_sftp_tab(self, connection: Connection) -> Any:
        """Open an SFTP browser tab for a connection."""
        from views.sftp_view import SftpTab
        sftp_tab = SftpTab(
            connection=connection,
            ssh_service=self._ssh_service,
        )

        page = self._tab_view.append(sftp_tab)
        sftp_tab._on_close = lambda t=sftp_tab: self._close_specific_tab_by_widget(t)
        
        page.set_title(sftp_tab.title)
        page.set_icon(Gio.ThemedIcon.new("folder-symbolic"))
        
        self._tab_view.set_selected_page(page)
        return sftp_tab

    def _close_specific_tab_by_widget(self, widget: Gtk.Widget) -> None:
        """Close a specific tab by its child widget."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            if page.get_child() == widget:
                self._tab_view.close_page(page)
                break

    def close_current_tab(self) -> None:
        """Close the currently selected tab."""
        page = self._tab_view.get_selected_page()
        if page:
            self._tab_view.close_page(page)

    # ── Event Handlers ────────────────────────────────────────

    def _on_close_page(self, tab_view: Adw.TabView, page: Adw.TabPage) -> bool:
        """Handle tab close request."""
        child = page.get_child()
        
        if hasattr(child, "connection") and child.connection:
            self._tabs.pop(child.connection.id, None)

        if hasattr(child, "terminate"):
            child.terminate()
        elif hasattr(child, "is_running") and child.is_running:
            child.terminate()

        tab_view.close_page_finish(page, True)
        return True  # We handle close ourselves

    def _on_page_selected(self, tab_view: Adw.TabView, _pspec) -> None:  # noqa: ANN001
        """Focus the terminal when a tab is selected."""
        page = tab_view.get_selected_page()
        if page:
            terminal_tab: TerminalTab = page.get_child()
            GLib.idle_add(lambda: terminal_tab.grab_focus() and False)

    def _on_create_local_tab(self, _overview: Adw.TabOverview) -> Adw.TabPage:
        """Create a new local shell from the tab overview."""
        self.open_local_tab()
        return self._tab_view.get_selected_page()

    def _on_page_attached(self, tab_view: Adw.TabView, page: Adw.TabPage, position: int) -> None:
        """When a page is transferred into this view (e.g. from tear off)."""
        child = page.get_child()
        if hasattr(child, "connection") and child.connection:
            self._tabs[child.connection.id] = page
        
        # Rewire close handler to point to this new view
        if hasattr(child, "_on_close"):
            child._on_close = lambda t=child: self._close_specific_tab_by_widget(t)

    def _on_page_detached(self, tab_view: Adw.TabView, page: Adw.TabPage, position: int) -> None:
        """When a page is transferred out of this view."""
        child = page.get_child()
        if hasattr(child, "connection") and child.connection:
            self._tabs.pop(child.connection.id, None)

    def find_sftp_tab_data(self, connection_id: str) -> tuple[Connection, dict] | None:
        """Find authentication info for an active SFTP tab."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            # Avoid circular import by checking class name or using local import
            if child.__class__.__name__ == "SftpTab":
                if hasattr(child, "_connection") and child._connection.id == connection_id:
                    return child._connection, child._auth_info
        return None
