# SPDX-License-Identifier: GPL-3.0-or-later

"""VTE terminal view — embeddable terminal widget for SSH sessions."""

from __future__ import annotations

import logging
import gettext
from typing import Callable, Any

_ = gettext.gettext
import gi
import os
import termios

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Vte", "3.91")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango, Vte  # noqa: E402

from models.connection import Connection
from services.ssh_service import SSHService

import json
from db.database import Database
from utils.themes import DEFAULT_THEME, ThemeDict

logger = logging.getLogger(__name__)


class TerminalTab(Gtk.Box):
    """A single terminal tab containing a VTE terminal + status bar."""

    def __init__(
        self,
        connection: Connection | None,
        ssh_command: Any | None, # LocalCommand or None
        ssh_service: SSHService,
        on_close: Callable[[], None] | None = None,
        on_os_detected: Callable[[str, str], None] | None = None,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self._connection = connection
        self._ssh_command = ssh_command
        self._ssh_service = ssh_service
        self._on_close = on_close
        self._on_os_detected = on_os_detected
        
        # State
        self._child_pid: int | None = None
        self._session_bridge: Any | None = None
        self._bg_task: Any = None
        self._pty: Vte.Pty | None = None
        self._pty_watch_id: int = 0
        self._vte_resize_timer_id: int = 0
        self._read_only = False
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
        return _("Local Shell")

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

        # Signals & Event Handling
        if self.is_remote:
            # Use a PTY bridge to capture ALL keyboard input (Control keys, Esc, Arrows, Fn keys, etc.)
            # This allows full interactive TUI support (vim, htop, etc.)
            try:
                self._pty = Vte.Pty.new_sync(Vte.PtyFlags.DEFAULT)
                self._terminal.set_pty(self._pty)
                self._pty_fd = self._pty.get_fd()
                
                # To capture user input from VTE, we must read from the PTY Slave.
                try:
                    # Get the slave path from the master FD
                    slave_path = os.ptsname(self._pty_fd)
                    # Open with O_NONBLOCK to play nice with GLib watch
                    self._slave_fd = os.open(slave_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                    
                    # IMPORTANT: Set the SLAVE side to raw mode.
                    # We must disable ECHO to prevent local characters from being sent back to VTE.
                    # We must disable ICANON to get key presses immediately (not line by line).
                    # We must disable ISIG so Ctrl+C is treated as data.
                    attrs = termios.tcgetattr(self._slave_fd)
                    # iflags
                    attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
                                | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
                    # oflags
                    attrs[1] &= ~termios.OPOST
                    # lflags
                    attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
                    # cflags
                    attrs[2] &= ~(termios.CSIZE | termios.PARENB)
                    attrs[2] |= termios.CS8
                    
                    termios.tcsetattr(self._slave_fd, termios.TCSANOW, attrs)
                    
                    logger.info(f"TerminalTab: PTY Bridge active on slave: {slave_path}")

                    # Watch the SLAVE FD for data coming FROM the VTE widget (user input)
                    self._pty_watch_id = GLib.io_add_watch(
                        self._slave_fd, 
                        GLib.IOCondition.IN | GLib.IOCondition.HUP | GLib.IOCondition.ERR, 
                        self._on_pty_input
                    )
                except Exception as te:
                    logger.error(f"TerminalTab: Failed to setup PTY bridge: {te}")
            except Exception as e:
                logger.error(f"Failed to initialize PTY bridge for remote terminal: {e}")

        # Signal connections for both local and remote for logging & sync
        self._terminal.connect("notify::column-count", self._on_vte_resize_property)
        self._terminal.connect("notify::row-count", self._on_vte_resize_property)

        if self.is_remote:
            self._terminal.connect("window-title-changed", self._on_title_changed)
        else:
            self._terminal.connect("child-exited", self._on_local_child_exited)
            self._terminal.connect("window-title-changed", self._on_title_changed)

        # Right-click context menu
        self._setup_context_menu()

        # Search bar
        self._search_bar = Gtk.SearchBar(halign=Gtk.Align.FILL)
        search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        search_box.add_css_class("toolbar")
        search_box.set_margin_start(12)
        search_box.set_margin_end(12)
        search_box.set_margin_top(6)
        search_box.set_margin_bottom(6)

        self._search_entry = Gtk.SearchEntry(hexpand=True)
        self._search_entry.set_placeholder_text(_("Find in terminal..."))
        search_box.append(self._search_entry)

        next_btn = Gtk.Button.new_from_icon_name("go-down-symbolic")
        next_btn.set_tooltip_text(_("Find next"))
        next_btn.connect("clicked", lambda *_: self._on_search_next())
        search_box.append(next_btn)

        prev_btn = Gtk.Button.new_from_icon_name("go-up-symbolic")
        prev_btn.set_tooltip_text(_("Find previous"))
        prev_btn.connect("clicked", lambda *_: self._on_search_prev())
        search_box.append(prev_btn)

        close_btn = Gtk.Button.new_from_icon_name("window-close-symbolic")
        close_btn.add_css_class("flat")
        close_btn.connect("clicked", lambda *_: self._search_bar.set_search_mode(False))
        search_box.append(close_btn)

        self._search_bar.set_child(search_box)
        self._search_bar.connect_entry(self._search_entry)
        self._search_entry.connect("search-changed", self._on_search_changed)
        self._search_entry.connect("activate", lambda *_: self._on_search_next())

        self.prepend(self._search_bar)

        # Scrolled container: In GTK4, for VTE it's more stable to use a Box + Scrollbar
        terminal_container = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, vexpand=True, hexpand=True)
        self._terminal.set_hexpand(True)
        self._terminal.set_vexpand(True)
        # Set a generous scrollback limit (100k lines)
        self._terminal.set_scrollback_lines(100000)
        
        terminal_container.append(self._terminal)
        
        # Add the vertical scrollbar and link it to the terminal's adjustment
        scrollbar = Gtk.Scrollbar(orientation=Gtk.Orientation.VERTICAL)
        scrollbar.set_adjustment(self._terminal.get_vadjustment())
        terminal_container.append(scrollbar)
        
        self.append(terminal_container)

        # Status bar
        self._status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._status_bar.add_css_class("toolbar")

        self._status_label = Gtk.Label(
            label=_("Connecting to {title}…").format(title=self.title) if self.is_remote else _("Spawning local shell..."),
            xalign=0,
            hexpand=True,
            ellipsize=3,
        )
        self._status_label.add_css_class("dim-label")
        self._status_label.add_css_class("caption")
        self._status_bar.append(self._status_label)
        self.append(self._status_bar)

    def _apply_theme(self) -> None:
        db = Database()
        db.open()
        theme_json = db.get_meta("terminal_theme", "")
        db.close()

        if theme_json:
            try:
                theme = json.loads(theme_json)
            except:
                theme = DEFAULT_THEME
        else:
            theme = DEFAULT_THEME

        bg = Gdk.RGBA()
        bg.parse(theme["background"])
        fg = Gdk.RGBA()
        fg.parse(theme["foreground"])
        
        palette = []
        for h in theme["palette"]:
            c = Gdk.RGBA()
            c.parse(h)
            palette.append(c)
        self._terminal.set_colors(fg, bg, palette)

        # Cursor color
        cursor_rgba = Gdk.RGBA()
        if cursor_rgba.parse(theme.get("cursor", theme["foreground"])):
            # VTE 0.70+ uses these
            self._terminal.set_color_cursor(cursor_rgba)

        # Emphasis for search matches and selection
        highlight_bg = Gdk.RGBA()
        highlight_bg.parse(theme.get("highlight_bg", "#f9e2af"))
        
        highlight_fg = Gdk.RGBA()
        highlight_fg.parse(theme.get("highlight_fg", theme["background"]))
        
        self._terminal.set_color_highlight(highlight_bg)
        self._terminal.set_color_highlight_foreground(highlight_fg)

    # ── Remote Process ─────────────────────────────────────────

    def _connect_remote(self) -> None:
        logger.info(f"TerminalTab: Starting remote connection to {self.title}")
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
            logger.info(f"TerminalTab: OS detection callback attached for {self.title}")
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
        self._status_label.set_label(_("Connected — {title}").format(title=self.title))
        
        # Immediate sync if we already have a size
        cols, rows = self._terminal.get_column_count(), self._terminal.get_row_count()
        if cols > 0 and rows > 0:
            logger.info(f"TerminalTab: Initial PTY resize to {cols}x{rows}")
            bridge.resize(cols, rows)
        
        # Delayed sync to ensure GTK layout is fully settled after being shown
        def _delayed_resize():
            if self._session_bridge:
                c, r = self._terminal.get_column_count(), self._terminal.get_row_count()
                if c > 0 and r > 0:
                    logger.debug(f"TerminalTab: Settled PTY resize to {c}x{r}")
                    self._session_bridge.resize(c, r)
            return False
        GLib.timeout_add(250, _delayed_resize)

    def _on_remote_error(self, msg: str) -> None:
        self._status_label.set_label(msg)
        self._print_terminal_error(msg)
        self._show_reconnect_prompt()
        
    def _on_remote_disconnected(self, exc: Exception | None) -> None:
        self._status_label.set_label(_("Disconnected: {exc}").format(exc=exc) if exc else _("Disconnected"))
        self._session_bridge = None
        self._show_reconnect_prompt()
        
    def _on_remote_output(self, data: bytes) -> None:
        self._terminal.feed(data)
        
    def _on_pty_input(self, fd: int, condition: GLib.IOCondition) -> bool:
        """Called when there is data to read from the PTY Slave (user input from VTE)."""
        if condition & (GLib.IOCondition.HUP | GLib.IOCondition.ERR):
            logger.info("TerminalTab: PTY Slave connection closed/error.")
            return False

        if condition & GLib.IOCondition.IN:
            try:
                # Read what VTE wrote to the PTY Master -> received at Slave
                data = os.read(fd, 4096)
                if data:
                    # logger.info(f"TerminalTab: Captured User Input: {data!r}")
                    if self._session_bridge and not self._read_only:
                        self._session_bridge.write(data)
            except (OSError, Exception) as e:
                logger.error(f"TerminalTab: PTY read error: {e}")
                return False
        return True
            
    def _on_vte_resize_property(self, terminal: Vte.Terminal, pspec: Any) -> None:
        """Handler for column/row notifications. Uses debouncing."""
        if self._vte_resize_timer_id:
            GLib.source_remove(self._vte_resize_timer_id)
            self._vte_resize_timer_id = 0

        # Debounce for 100ms
        self._vte_resize_timer_id = GLib.timeout_add(100, self._do_vte_resize, terminal)

    def _do_vte_resize(self, terminal: Vte.Terminal) -> bool:
        self._vte_resize_timer_id = 0
        
        cols, rows = terminal.get_column_count(), terminal.get_row_count()
        width, height = terminal.get_width(), terminal.get_height()
        
        logger.info(f"TerminalTab: Resize Event - Pixels: {width}x{height}, Grid: {cols}x{rows}, Remote: {self.is_remote}")
        
        if self._session_bridge:
            if cols > 0 and rows > 0:
                logger.info(f"TerminalTab: Syncing remote PTY to {cols}x{rows}")
                self._session_bridge.resize(cols, rows)
        return False

    def _on_remote_exited(self, exit_status: int) -> None:
        self._status_label.set_label(_("Exited with code {exit_status}").format(exit_status=exit_status))
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
            self._status_label.set_label(_("Error: {error}").format(error=error.message))
            return
        self._child_pid = pid
        self._status_label.set_label(_("Local Shell"))

    def _on_local_child_exited(self, terminal: Vte.Terminal, exit_status: int) -> None:
        self._child_pid = None
        self._status_label.set_label(_("Exited code {exit_status}").format(exit_status=exit_status >> 8))
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
            self._status_label.set_label(_("Reconnecting…"))
            self._terminal.reset(True, True)
            if self.is_remote:
                self._connect_remote()
            else:
                self._spawn_local()

    def _on_title_changed(self, terminal: Vte.Terminal) -> None:
        pass

    def _setup_context_menu(self) -> None:
        """Create a right-click context menu for the terminal."""
        menu = Gio.Menu()
        
        section_edit = Gio.Menu()
        section_edit.append(_("Copy"), "term.copy")
        section_edit.append(_("Paste"), "term.paste")
        menu.append_section(None, section_edit)
        
        section_tools = Gio.Menu()
        section_tools.append(_("Find…"), "term.find")
        section_tools.append(_("Read-only"), "term.read-only")
        menu.append_section(None, section_tools)
        
        section_view = Gio.Menu()
        section_view.append(_("Select All"), "term.select-all")
        section_view.append(_("Clear"), "term.clear")
        menu.append_section(None, section_view)

        self._popover = Gtk.PopoverMenu.new_from_model(menu)
        self._popover.set_parent(self._terminal)
        self._popover.set_has_arrow(False)

        action_group = Gio.SimpleActionGroup()
        
        copy_action = Gio.SimpleAction.new("copy", None)
        copy_action.connect("activate", lambda *_: self.copy_clipboard())
        action_group.add_action(copy_action)
        
        paste_action = Gio.SimpleAction.new("paste", None)
        paste_action.connect("activate", lambda *_: self.paste_clipboard())
        action_group.add_action(paste_action)

        select_all_action = Gio.SimpleAction.new("select-all", None)
        select_all_action.connect("activate", lambda *_: self._terminal.select_all())
        action_group.add_action(select_all_action)

        clear_action = Gio.SimpleAction.new("clear", None)
        clear_action.connect("activate", lambda *_: self._on_clear_terminal())
        action_group.add_action(clear_action)

        find_action = Gio.SimpleAction.new("find", None)
        find_action.connect("activate", lambda *_: self._search_bar.set_search_mode(True))
        action_group.add_action(find_action)

        ro_action = Gio.SimpleAction.new_stateful("read-only", None, GLib.Variant.new_boolean(False))
        ro_action.connect("change-state", self._on_read_only_change)
        action_group.add_action(ro_action)

        self._terminal.insert_action_group("term", action_group)

        # Right-click gesture
        click_gesture = Gtk.GestureClick.new()
        click_gesture.set_button(3)  # Secondary button
        click_gesture.connect("pressed", self._on_right_click)
        self._terminal.add_controller(click_gesture)

    def _on_right_click(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        # Move popover to the click location
        rect = Gdk.Rectangle()
        rect.x, rect.y = int(x), int(y)
        rect.width = rect.height = 1
        self._popover.set_pointing_to(rect)
        self._popover.popup()

    def _on_read_only_change(self, action: Gio.SimpleAction, state: GLib.Variant) -> None:
        self._read_only = state.get_boolean()
        self._terminal.set_input_enabled(not self._read_only)
        action.set_state(state)
        
        # Visual feedback in status
        if self._read_only:
            self._status_label.add_css_class("error") # Just to make it stand out or a new color
        else:
            self._status_label.remove_css_class("error")

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        text = entry.get_text()
        if not text:
            self._terminal.search_set_regex(None, 0)
            self._terminal.unselect_all()
            return

        try:
            # REGEX_FLAGS_DEFAULT should be available
            regex = Vte.Regex.new_for_search(text, -1, 0)
            self._terminal.search_set_regex(regex, 0)
            self._terminal.search_set_wrap_around(True)
            self._on_search_next()
        except:
            pass

    def _on_search_next(self) -> None:
        self._terminal.search_find_next()

    def _on_search_prev(self) -> None:
        self._terminal.search_find_previous()

    def _on_clear_terminal(self) -> None:
        """Reset terminal and send a clear signal to the shell."""
        self._terminal.reset(True, True)
        if self._session_bridge:
            # Send Ctrl+L to remote shell to get a new prompt
            self._session_bridge.write(b"\x0c")
        else:
            # Send Ctrl+L to local shell
            self._terminal.feed_child(b"\x0c")

    def copy_clipboard(self) -> None:
        self._terminal.copy_clipboard_format(Vte.Format.TEXT)

    def paste_clipboard(self) -> None:
        self._terminal.paste_clipboard()

    def grab_focus(self) -> bool:  # type: ignore[override]
        return self._terminal.grab_focus()

    def terminate(self) -> None:
        if self._pty_watch_id:
            GLib.source_remove(self._pty_watch_id)
            self._pty_watch_id = 0
            
        if self._vte_resize_timer_id:
            GLib.source_remove(self._vte_resize_timer_id)
            self._vte_resize_timer_id = 0
            
        if hasattr(self, "_slave_fd") and self._slave_fd:
            try:
                os.close(self._slave_fd)
                self._slave_fd = 0
            except: pass

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
            on_os_detected=on_os_detected,
        )

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
        
        page.set_title(_("Local Shell"))
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

    def notify_connection_updated(self, connection: Connection) -> None:
        """Update any open tabs that are using this connection."""
        page = self._tabs.get(connection.id)
        if page:
            logger.info(f"TerminalTabView: Syncing open tab for connection {connection.id}")
            child = page.get_child()
            if hasattr(child, "_connection") and child._connection:
                # Update critical fields in place to keep references valid but data fresh
                old_os = child._connection.os_id
                child._connection.os_id = connection.os_id
                logger.info(f"TerminalTabView: Updated child connection os_id for {connection.id} from '{old_os}' to '{connection.os_id}'")
                child._connection.name = connection.name
                child._connection.hostname = connection.hostname
                child._connection.username = connection.username
                child._connection.port = connection.port
                
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

    def refresh_theme(self) -> None:
        """Refresh theme for all open terminal tabs."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            if hasattr(child, "_apply_theme"):
                child._apply_theme()
