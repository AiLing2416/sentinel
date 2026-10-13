# SPDX-License-Identifier: GPL-3.0-or-later

"""VTE terminal view — embeddable terminal widget for SSH sessions."""

from __future__ import annotations

import asyncio
import logging
import gettext
from typing import Callable, Any

_ = gettext.gettext
import gi
import os
import termios
import time

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Vte", "3.91")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango, Vte  # noqa: E402

from models.connection import Connection
from services.ssh_service import SSHService

import json
from db.database import Database
from utils.themes import DEFAULT_THEME, ThemeDict
from utils.osc_parser import Osc52Parser

logger = logging.getLogger(__name__)

_THEME_CACHE: ThemeDict | None = None
_CONFIG_CACHE: dict[str, Any] | None = None


def get_terminal_theme(force_refresh: bool = False) -> ThemeDict:
    """Get the terminal theme from database, with caching."""
    global _THEME_CACHE
    if _THEME_CACHE is None or force_refresh:
        db = Database()
        try:
            db.open()
            theme_json = db.get_meta("terminal_theme", "")
            if theme_json:
                try:
                    _THEME_CACHE = json.loads(theme_json)
                except Exception:
                    logger.error("Failed to parse terminal theme JSON")
                    _THEME_CACHE = DEFAULT_THEME
            else:
                _THEME_CACHE = DEFAULT_THEME
        except Exception as e:
            logger.error(f"Failed to load terminal theme from database: {e}")
            _THEME_CACHE = DEFAULT_THEME
        finally:
            try:
                db.close()
            except Exception:
                pass

    return _THEME_CACHE


def get_terminal_config(force_refresh: bool = False) -> dict[str, Any]:
    """Get basic terminal settings from database, with caching."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None or force_refresh:
        db = Database()
        try:
            db.open()
            font_family = db.get_meta("terminal_font_family", "Monospace")
            font_size = db.get_meta("terminal_font_size", "11")
            scrollback = db.get_meta("terminal_scrollback_lines", "10000")
            cursor_shape = db.get_meta("terminal_cursor_shape", "block")
            cursor_blink = db.get_meta("terminal_cursor_blink", "system")
            enable_osc52 = db.get_meta("terminal_enable_osc52", "true") == "true"
            enable_hyperlinks = db.get_meta("terminal_enable_hyperlinks", "true") == "true"
            search_forward_keys = db.get_meta("terminal_search_forward_keys", "true") == "true"
            _CONFIG_CACHE = {
                "font_family": font_family if font_family else "Monospace",
                "font_size": int(font_size) if font_size and font_size.isdigit() else 11,
                "scrollback_lines": int(scrollback) if scrollback and scrollback.isdigit() else 10000,
                "cursor_shape": cursor_shape if cursor_shape else "block",
                "cursor_blink": cursor_blink if cursor_blink else "system",
                "enable_osc52": enable_osc52,
                "enable_hyperlinks": enable_hyperlinks,
                "search_forward_keys": search_forward_keys,
            }
        except Exception as e:
            logger.error(f"Failed to load terminal config from database: {e}")
            _CONFIG_CACHE = {
                "font_family": "Monospace",
                "font_size": 11,
                "scrollback_lines": 10000,
                "cursor_shape": "block",
                "cursor_blink": "system",
                "enable_osc52": True,
                "enable_hyperlinks": True,
                "search_forward_keys": True,
            }
        finally:
            try:
                db.close()
            except Exception:
                pass

    return _CONFIG_CACHE


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
        self._last_eof_time: float = 0
        self._reconnect_sid: int = 0
        self.is_remote = self._connection is not None
        # Output held back while the user is selecting text (VTE clears the
        # selection whenever the underlying content is rewritten)
        self._selecting: bool = False
        # Output is also held back while the search bar is open
        self._searching: bool = False
        self._has_output: bool = False
        self._held_output = bytearray()

        # OSC 52 & Hyperlinks state
        self._osc52_parser = Osc52Parser(self._on_osc52_clipboard)
        self._enable_osc52: bool = True
        self._enable_hyperlinks: bool = True
        self._hovered_uri: str | None = None
        self._osc8_uri: str | None = None
        self._match_uri: str | None = None
        self._context_uri: str | None = None
        self._current_status_text: str = ""
        self._url_match_tag: int = -1
        self._last_mouse_x: float = -1.0
        self._last_mouse_y: float = -1.0

        self._build_ui()
        
        if self.is_remote:
            self._connect_remote()
        else:
            self._start_local_session()

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
        # Enable CJK character width support
        os.environ["VTE_CJK_WIDTH"] = "1"

        # Terminal widget
        self._terminal = Vte.Terminal()
        self._terminal.set_vexpand(True)
        self._terminal.set_hexpand(True)

        # Terminal appearance
        self._terminal.set_scroll_on_output(True)
        self._terminal.set_scroll_on_keystroke(True)
        self._terminal.set_mouse_autohide(True)

        self.apply_terminal_config()
        self._apply_theme()

        # Register URL regex pattern for auto-detecting web and common URIs
        try:
            # PCRE2_MULTILINE = 0x00000400
            url_pattern = r"(https?|ftp|file|ssh|mailto)://[^\s/$.?#].[^\s]*"
            url_regex = Vte.Regex.new_for_match(url_pattern, -1, 0x00000400)
            self._url_match_tag = self._terminal.match_add_regex(url_regex, 0)
            self._terminal.match_set_cursor_name(self._url_match_tag, "pointer")
        except Exception as e:
            logger.warning(f"TerminalTab: Failed to register URL regex in VTE: {e}")

        # Signal connections for hyperlinks
        self._terminal.connect("hyperlink-hover-uri-changed", self._on_hyperlink_hover_uri_changed)

        # Mouse motion controller to detect hover over links / regex matches and pointer avoidance
        motion_ctrl = Gtk.EventControllerMotion.new()
        motion_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        motion_ctrl.connect("motion", self._on_mouse_motion)
        motion_ctrl.connect("leave", self._on_mouse_leave)
        self._terminal.add_controller(motion_ctrl)

        # Left-click gesture for Ctrl + Click to open hyperlinks
        left_click_gesture = Gtk.GestureClick.new()
        left_click_gesture.set_button(1)
        left_click_gesture.connect("pressed", self._on_left_click)
        self._terminal.add_controller(left_click_gesture)

        # Scroll intent detection (capture phase, never consumes events):
        # scrolling up or pressing the mouse (start of a selection) suspends
        # "scroll on output" so incoming output cannot pull the view away.
        scroll_ctrl = Gtk.EventControllerScroll.new(Gtk.EventControllerScrollFlags.VERTICAL)
        scroll_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        scroll_ctrl.connect("scroll", self._on_user_scroll)
        self._terminal.add_controller(scroll_ctrl)

        press_gesture = Gtk.GestureClick.new()
        press_gesture.set_button(1)
        press_gesture.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        press_gesture.connect("pressed", self._on_selection_press)
        self._terminal.add_controller(press_gesture)

        # Button release is observed with a legacy controller so it is seen
        # even when VTE's own drag handling claims the event sequence.
        release_ctrl = Gtk.EventControllerLegacy.new()
        release_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        release_ctrl.connect("event", self._on_terminal_event)
        self._terminal.add_controller(release_ctrl)

        key_ctrl = Gtk.EventControllerKey.new()
        key_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        key_ctrl.connect("key-pressed", self._on_key_unfreeze)
        self._terminal.add_controller(key_ctrl)

        self._terminal.connect("selection-changed", lambda *_: self._flush_held_output())

        # Signals & Event Handling
        # Use a PTY bridge to capture ALL keyboard input (Control keys, Esc, Arrows, Fn keys, etc.)
        # This allows full interactive TUI support (vim, htop, etc.) for both local and remote.
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
                attrs = termios.tcgetattr(self._slave_fd)
                attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
                            | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
                attrs[1] &= ~termios.OPOST
                attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
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
            logger.error(f"TerminalTab: Failed to initialize PTY bridge: {e}")

        # Signal connections for both local and remote for logging & sync
        if self.is_remote:
            self._terminal.connect("window-title-changed", self._on_title_changed)
        else:
            self._terminal.connect("child-exited", self._on_local_child_exited)
            self._terminal.connect("window-title-changed", self._on_title_changed)

        # Right-click context menu
        self._setup_context_menu()

        # Floating, draggable search box (overlaid on the terminal, per session)
        self._search_pos: tuple[int, int] | None = None
        self._search_drag_origin: tuple[int, int] = (0, 0)
        self._search_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._search_box.add_css_class("osd")
        self._search_box.add_css_class("toolbar")
        self._search_box.set_halign(Gtk.Align.START)
        self._search_box.set_valign(Gtk.Align.START)
        self._search_box.set_visible(False)
        search_box = self._search_box

        grip = Gtk.Image.new_from_icon_name("list-drag-handle-symbolic")
        grip.set_tooltip_text(_("Drag to move"))
        grip.set_cursor(Gdk.Cursor.new_from_name("grab"))
        self._search_grip = grip
        search_box.append(grip)

        self._search_entry = Gtk.SearchEntry()
        self._search_entry.set_placeholder_text(_("Find in terminal..."))
        self._search_entry.set_size_request(220, -1)
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
        close_btn.set_tooltip_text(_("Close"))
        close_btn.connect("clicked", lambda *_: self._set_search_visible(False))
        search_box.append(close_btn)

        self._search_entry.connect("search-changed", self._on_search_changed)
        self._search_entry.connect("activate", lambda *_: self._on_search_next())
        self._search_entry.connect("stop-search", lambda *_: self._set_search_visible(False))

        search_key_ctrl = Gtk.EventControllerKey.new()
        search_key_ctrl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        search_key_ctrl.connect("key-pressed", self._on_search_shortcut)
        self._terminal.add_controller(search_key_ctrl)

        # Scrolled container: In GTK4, for VTE it's more stable to use a Box + Scrollbar
        terminal_container = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, vexpand=True, hexpand=True)
        self._terminal.set_hexpand(True)
        self._terminal.set_vexpand(True)
        
        # GTK4 Hack: Reliable resize detection via DrawingArea in an Overlay
        # (Standard signals like size-allocate are gone or unreliable on VTE in GTK4)
        self._resize_sensor = Gtk.DrawingArea()
        self._resize_sensor.set_hexpand(True)
        self._resize_sensor.set_vexpand(True)
        # Handle resize via simple lambda to our existing logic
        self._resize_sensor.connect("resize", lambda _da, _w, _h: self._on_vte_resize_property())
        
        overlay = Gtk.Overlay(hexpand=True, vexpand=True)
        overlay.set_child(self._terminal)
        overlay.add_overlay(self._resize_sensor)
        overlay.add_overlay(self._search_box)
        self._search_overlay = overlay

        drag = Gtk.GestureDrag.new()
        drag.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        drag.connect("drag-begin", self._on_search_drag_begin)
        drag.connect("drag-update", self._on_search_drag_update)
        overlay.add_controller(drag)
        # In GTK4, to make an overlay pass through mouse events, set its target property.
        self._resize_sensor.set_can_target(False)

        terminal_container.append(overlay)
        
        # Add the vertical scrollbar and link it to the terminal's adjustment
        scrollbar = Gtk.Scrollbar(orientation=Gtk.Orientation.VERTICAL)
        vadjust = self._terminal.get_vadjustment()
        scrollbar.set_adjustment(vadjust)
        self._scroll_handler_id = vadjust.connect("value-changed", self._on_scroll_value_changed)
        terminal_container.append(scrollbar)
        
        self.append(terminal_container)

        # Floating status bubble (Chrome-style): only visible while active,
        # sized to its content, anchored to the bottom-left of the terminal.
        self._status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self._status_bar.add_css_class("terminal-status-bubble")
        self._status_bar.set_halign(Gtk.Align.START)
        self._status_bar.set_valign(Gtk.Align.END)
        self._status_bar.set_can_target(False)
        self._status_bar.set_visible(False)
        self._status_hide_id: int = 0
        self._status_persistent: bool = False

        initial_status = _("Connecting to {title}…").format(title=self.title) if self.is_remote else _("Spawning local shell...")
        self._current_status_text = initial_status
        self._status_label = Gtk.Label(
            label=initial_status,
            xalign=0,
            ellipsize=Pango.EllipsizeMode.END,
            max_width_chars=100,
            margin_start=8,
            margin_end=8,
            margin_top=3,
            margin_bottom=3,
        )
        self._status_label.add_css_class("dim-label")
        self._status_label.add_css_class("caption")
        self._status_label.set_can_target(False)
        self._status_bar.append(self._status_label)
        self._search_overlay.add_overlay(self._status_bar)
        self._show_overlay_text(initial_status, timeout_ms=4000)

    def _update_pointer_avoidance(self, x: float, y: float) -> None:
        """Avoid mouse pointer by shifting bubble between bottom corners when pointer approaches."""
        term_w = self._terminal.get_width()
        term_h = self._terminal.get_height()
        if term_w <= 0 or term_h <= 0:
            term_w = self._search_overlay.get_width()
            term_h = self._search_overlay.get_height()
        if term_w <= 0 or term_h <= 0 or term_w < 350:
            return

        bubble_w = self._status_bar.get_width()
        bubble_h = self._status_bar.get_height()
        detect_w = max(bubble_w, 200) + 24
        detect_h = max(bubble_h, 28) + 24

        is_near_bottom_left = (x < detect_w) and (y > term_h - detect_h)
        is_near_bottom_right = (x > term_w - detect_w) and (y > term_h - detect_h)

        current_align = self._status_bar.get_halign()
        if current_align == Gtk.Align.START:
            target_align = Gtk.Align.END if is_near_bottom_left else Gtk.Align.START
        else:
            target_align = Gtk.Align.START if (is_near_bottom_right or not is_near_bottom_left) else Gtk.Align.END

        if current_align != target_align:
            self._status_bar.set_halign(target_align)
            self._status_bar.queue_resize()
            self._search_overlay.queue_allocate()

    def _show_overlay_text(self, text: str, timeout_ms: int = 0) -> None:
        """Show the floating status bubble; auto-hide after timeout_ms if > 0."""
        if self._status_hide_id:
            GLib.source_remove(self._status_hide_id)
            self._status_hide_id = 0
        self._status_label.set_label(text)
        if self._last_mouse_x >= 0 and self._last_mouse_y >= 0:
            self._update_pointer_avoidance(self._last_mouse_x, self._last_mouse_y)
        else:
            if self._status_bar.get_halign() != Gtk.Align.START:
                self._status_bar.set_halign(Gtk.Align.START)
                self._status_bar.queue_resize()
                self._search_overlay.queue_allocate()
        self._status_bar.set_visible(True)
        if timeout_ms > 0:
            self._status_hide_id = GLib.timeout_add(timeout_ms, self._hide_overlay_text)

    def _hide_overlay_text(self) -> bool:
        self._status_hide_id = 0
        if not self._hovered_uri and not self._status_persistent:
            self._status_bar.set_visible(False)
        return False

    def _set_status(self, text: str, persistent: bool = False) -> None:
        """Update current status text; flash it briefly unless hovering a link or persistent."""
        self._current_status_text = text
        self._status_persistent = persistent
        if persistent:
            self._status_bar.add_css_class("status-disconnected")
        else:
            self._status_bar.remove_css_class("status-disconnected")

        if not self._hovered_uri:
            self._show_overlay_text(text, timeout_ms=0 if persistent else 4000)

    def _restore_status_label(self) -> None:
        """Hide the floating bubble once the link hover ends, or restore persistent status."""
        if self._status_hide_id:
            GLib.source_remove(self._status_hide_id)
            self._status_hide_id = 0
        if self._status_persistent and self._current_status_text:
            self._show_overlay_text(self._current_status_text, timeout_ms=0)
        else:
            self._status_bar.set_visible(False)

    def apply_terminal_config(self) -> None:
        """Apply basic terminal settings (font, size, scrollback, cursor, osc52, hyperlinks)."""
        cfg = get_terminal_config()

        font_str = f"{cfg['font_family']} {cfg['font_size']}"
        font_desc = Pango.FontDescription.from_string(font_str)
        self._terminal.set_font(font_desc)

        self._terminal.set_scrollback_lines(cfg['scrollback_lines'])

        shape_map = {
            "block": Vte.CursorShape.BLOCK,
            "ibeam": Vte.CursorShape.IBEAM,
            "underline": Vte.CursorShape.UNDERLINE,
        }
        self._terminal.set_cursor_shape(shape_map.get(cfg['cursor_shape'], Vte.CursorShape.BLOCK))

        blink_map = {
            "system": Vte.CursorBlinkMode.SYSTEM,
            "on": Vte.CursorBlinkMode.ON,
            "off": Vte.CursorBlinkMode.OFF,
        }
        self._terminal.set_cursor_blink_mode(blink_map.get(cfg['cursor_blink'], Vte.CursorBlinkMode.SYSTEM))

        self._enable_osc52 = cfg.get("enable_osc52", True)
        self._enable_hyperlinks = cfg.get("enable_hyperlinks", True)
        self._search_forward_keys = cfg.get("search_forward_keys", True)
        self._terminal.set_allow_hyperlink(self._enable_hyperlinks)

    def _apply_theme(self) -> None:
        theme = get_terminal_theme()

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
        """Start the remote SSH connection and session."""
        if self._bg_task:
            self._bg_task.cancel()
            self._bg_task = None
            
        logger.info(f"TerminalTab: Starting remote connection to {self.title}")
        self._set_status(_("Connecting to {title}…").format(title=self.title), persistent=False)
        from views.dialogs import prompt_password, prompt_host_key, prompt_vault_unlock, prompt_vault_item_selection
        from services.vault_service import VaultService
        
        def _ask_password(conn, resolve):
            from utils.secure import SecureBytes
            def _on_resolved(password: SecureBytes | None, remember: bool = False):
                if password and remember:
                    from services.vault_manager import VaultManager
                    VaultManager.get().cache_password(
                        item_id=conn.id,
                        label=f"Password for {conn.username}@{conn.hostname}",
                        password=password,
                        hostname=conn.hostname,
                        username=conn.username
                    )
                resolve(password)
            prompt_password(
                self.get_root(),
                f"Password for {conn.hostname}",
                f"{conn.username}@{conn.hostname}",
                _on_resolved,
                show_remember=True
            )
            
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
            status_cb=self._set_status
        )
        self._bg_task = self._ssh_service.engine.run_coroutine(coro)

    # ── Hyperlinks & OSC 52 ───────────────────────────────────

    def _get_uri_at_position(self, x: float, y: float) -> str | None:
        """Find an OSC 8 hyperlink or matched regex URL at coordinates (x, y)."""
        # 1. Check explicit OSC 8 hyperlink
        try:
            uri = self._terminal.check_hyperlink_at(x, y)
            if uri:
                return uri
        except Exception:
            pass

        # 2. Check regex matched URL
        try:
            match_res = self._terminal.check_match_at(x, y)
            if match_res:
                match_str = match_res[0] if isinstance(match_res, tuple) else match_res
                if match_str:
                    return match_str
        except Exception:
            pass

        return None

    def _open_uri(self, uri: str) -> None:
        """Launch default browser for the given URI."""
        if not uri:
            return
        logger.info(f"TerminalTab: Opening URI: {uri}")
        try:
            root = self.get_root()
            Gtk.show_uri(root, uri, Gdk.CURRENT_TIME)
        except Exception as e:
            logger.warning(f"TerminalTab: Gtk.show_uri failed for {uri}: {e}")
            try:
                Gio.AppInfo.launch_default_for_uri(uri, None)
            except Exception as e2:
                logger.error(f"TerminalTab: Failed to open URI {uri}: {e2}")

    def _copy_link_address(self, uri: str | None) -> None:
        """Copy the given URI to system clipboard."""
        if not uri:
            return
        try:
            display = Gdk.Display.get_default()
            if display:
                clipboard = display.get_clipboard()
                if clipboard:
                    clipboard.set(uri)
                    logger.info(f"TerminalTab: Link copied to clipboard: {uri}")
        except Exception as e:
            logger.error(f"TerminalTab: Failed to copy link address: {e}")

    def _on_hyperlink_hover_uri_changed(self, terminal: Vte.Terminal, uri: str | None, bbox: Any) -> None:
        """Called when mouse hovers over an OSC 8 hyperlink."""
        if not self._enable_hyperlinks:
            return
        self._osc8_uri = uri or None
        self._update_hovered_uri()

    def _on_mouse_motion(self, controller: Gtk.EventControllerMotion, x: float, y: float) -> None:
        """Track mouse motion to provide instant hover feedback on links and avoid mouse pointer."""
        self._last_mouse_x = x
        self._last_mouse_y = y
        self._update_pointer_avoidance(x, y)
        if not self._enable_hyperlinks:
            return
        self._match_uri = self._get_uri_at_position(x, y)
        self._update_hovered_uri()

    def _on_mouse_leave(self, controller: Gtk.EventControllerMotion) -> None:
        """Clear link preview and reset pointer avoidance when mouse leaves the terminal widget."""
        self._last_mouse_x = -1.0
        self._last_mouse_y = -1.0
        self._osc8_uri = None
        self._match_uri = None
        self._update_hovered_uri()
        if self._status_bar.get_halign() != Gtk.Align.START:
            self._status_bar.set_halign(Gtk.Align.START)
            self._status_bar.queue_resize()
            self._search_overlay.queue_allocate()

    def _update_hovered_uri(self) -> None:
        """Combine OSC 8 and regex hover sources and refresh the floating link label."""
        uri = self._osc8_uri or self._match_uri
        if uri == self._hovered_uri:
            return
        self._hovered_uri = uri
        if uri:
            self._show_overlay_text(_("Link: {uri} (Ctrl+Click to open)").format(uri=uri))
        else:
            self._restore_status_label()

    def _on_left_click(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        """Handle Ctrl+Left Click to open hyperlinks / URLs."""
        if not self._enable_hyperlinks:
            return
        event = gesture.get_current_event()
        if not event:
            return
        modifiers = event.get_modifier_state()
        if not (modifiers & Gdk.ModifierType.CONTROL_MASK):
            return

        uri = self._get_uri_at_position(x, y)
        if uri:
            self._open_uri(uri)

    def _on_osc52_clipboard(self, target: str, text: str) -> None:
        """Handle clipboard content from remote/local OSC 52 sequences."""
        if not self._enable_osc52:
            return

        def _update_clipboard():
            try:
                display = Gdk.Display.get_default()
                if not display:
                    return False

                # 'c' or default: update clipboard
                if "c" in target or not target:
                    clipboard = display.get_clipboard()
                    if clipboard:
                        clipboard.set(text)

                # 'p': update primary clipboard
                if "p" in target:
                    primary = display.get_primary_clipboard()
                    if primary:
                        primary.set(text)

                logger.debug(f"TerminalTab: OSC 52 updated system clipboard ({len(text)} chars)")
            except Exception as e:
                logger.error(f"TerminalTab: Failed to set OSC 52 clipboard: {e}")
            return False

        GLib.idle_add(_update_clipboard)

    def _on_remote_connected(self, bridge: Any) -> None:
        self._session_bridge = bridge
        self._set_status(_("Connected — {title}").format(title=self.title), persistent=False)
        
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
        self._set_status(msg, persistent=True)
        self._show_reconnect_prompt()
        
    def _on_remote_disconnected(self, exc: Exception | None) -> None:
        if exc:
            if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                err_text = _("Connection timed out")
            else:
                detail = str(exc).strip() or type(exc).__name__
                err_text = _("Disconnected: {exc}").format(exc=detail)
        else:
            err_text = _("Disconnected")
        self._set_status(err_text, persistent=True)
        self._session_bridge = None
        # Only show reconnect if the background task has truly finished
        # This prevents the prompt during host key trust retries
        if self._bg_task and self._bg_task.done():
            self._show_reconnect_prompt()
        
    # Safety cap so a forgotten selection cannot buffer unbounded output
    _MAX_HELD_OUTPUT = 4 * 1024 * 1024

    def _output_frozen(self) -> bool:
        if self._selecting:
            return True
        if self._searching:
            # With key forwarding the shell stays interactive: keep writing
            # (auto-scroll is already suspended). The current search match is
            # itself a selection, so it must not freeze output either.
            return not self._search_forward_keys
        return self._terminal.get_has_selection()

    _SEARCH_MARGIN = 12

    def _set_search_visible(self, visible: bool) -> None:
        """Show/hide the floating search box. Pause terminal writes while open."""
        if visible == self._searching:
            if visible:
                self._search_entry.grab_focus()
            return
        self._searching = visible
        self._search_box.set_visible(visible)
        if visible:
            self._suspend_follow()
            GLib.idle_add(self._place_search_box)
            self._search_entry.grab_focus()
            return
        self._terminal.search_set_regex(None, 0)
        self._terminal.unselect_all()
        self._flush_held_output()
        self._terminal.grab_focus()

    def _search_bounds(self) -> tuple[int, int]:
        """Return the max (x, y) margin so the box stays inside the terminal."""
        _min_w, nat_w, _a, _b = self._search_box.measure(Gtk.Orientation.HORIZONTAL, -1)
        _min_h, nat_h, _c, _d = self._search_box.measure(Gtk.Orientation.VERTICAL, -1)
        nat_w -= self._search_box.get_margin_start() + self._search_box.get_margin_end()
        nat_h -= self._search_box.get_margin_top() + self._search_box.get_margin_bottom()
        max_x = max(0, self._search_overlay.get_width() - nat_w)
        max_y = max(0, self._search_overlay.get_height() - nat_h)
        return max_x, max_y

    def _apply_search_pos(self, x: int, y: int) -> None:
        max_x, max_y = self._search_bounds()
        x = max(0, min(int(x), max_x))
        y = max(0, min(int(y), max_y))
        self._search_pos = (x, y)
        self._search_box.set_margin_start(x)
        self._search_box.set_margin_top(y)

    def _place_search_box(self) -> bool:
        """Place the box at the remembered position (default: top-right)."""
        if self._search_pos is None:
            max_x, _max_y = self._search_bounds()
            self._apply_search_pos(max_x - self._SEARCH_MARGIN, self._SEARCH_MARGIN)
        else:
            self._apply_search_pos(*self._search_pos)
        return False

    def _on_search_drag_begin(self, gesture: Gtk.GestureDrag, x: float, y: float) -> None:
        # Gesture lives on the stationary overlay, so offsets stay in a fixed frame.
        picked = self._search_overlay.pick(x, y, Gtk.PickFlags.DEFAULT)
        if (not self._searching or picked is None
                or (picked is not self._search_grip
                    and not picked.is_ancestor(self._search_grip))):
            self._search_dragging = False
            gesture.set_state(Gtk.EventSequenceState.DENIED)
            return
        self._search_dragging = True
        gesture.set_state(Gtk.EventSequenceState.CLAIMED)
        self._search_drag_origin = self._search_pos or (
            self._search_box.get_margin_start(), self._search_box.get_margin_top())

    def _on_search_drag_update(self, gesture: Gtk.GestureDrag, dx: float, dy: float) -> None:
        if not getattr(self, "_search_dragging", False):
            return
        ox, oy = self._search_drag_origin
        self._apply_search_pos(ox + dx, oy + dy)

    def _on_search_shortcut(self, controller: Gtk.EventControllerKey, keyval: int,
                            keycode: int, state: Gdk.ModifierType) -> bool:
        """Ctrl+Shift+F opens the in-terminal search box."""
        mask = Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK
        if keyval in (Gdk.KEY_F, Gdk.KEY_f) and (state & mask) == mask:
            self._set_search_visible(True)
            return True
        if self._searching and not self._search_forward_keys:
            if keyval == Gdk.KEY_Escape:
                self._set_search_visible(False)
            elif (state & mask) != mask:
                # Swallow input so it never reaches the remote shell
                return True
        return False

    def _on_selection_press(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        self._selecting = True
        self._suspend_follow()

    def _on_terminal_event(self, controller: Gtk.EventControllerLegacy, event: Gdk.Event) -> bool:
        if (event.get_event_type() == Gdk.EventType.BUTTON_RELEASE
                and event.get_button() == 1):
            self._selecting = False
            self._flush_held_output()
        return False

    def _on_key_unfreeze(self, controller: Gtk.EventControllerKey, keyval: int,
                         keycode: int, state: Gdk.ModifierType) -> bool:
        """Typing resumes live output; copy shortcuts and bare modifiers do not."""
        modifier_keys = {
            Gdk.KEY_Shift_L, Gdk.KEY_Shift_R, Gdk.KEY_Control_L, Gdk.KEY_Control_R,
            Gdk.KEY_Alt_L, Gdk.KEY_Alt_R, Gdk.KEY_Super_L, Gdk.KEY_Super_R,
        }
        if keyval in modifier_keys or (state & Gdk.ModifierType.CONTROL_MASK
                                       and state & Gdk.ModifierType.SHIFT_MASK):
            return False
        if self._held_output or self._terminal.get_has_selection():
            self._terminal.unselect_all()
            self._selecting = False
            self._flush_held_output()
        return False

    def _flush_held_output(self) -> None:
        """Feed buffered output once the user is no longer selecting."""
        if self._output_frozen() or not self._held_output:
            return
        data = bytes(self._held_output)
        self._held_output.clear()
        self._feed_output(data)

    def _on_remote_output(self, data: bytes) -> None:
        # An empty terminal has nothing to protect; holding the very first
        # output (login banner/prompt) would look like a hung connection.
        if self._output_frozen() and self._has_output:
            self._held_output.extend(data)
            if len(self._held_output) <= self._MAX_HELD_OUTPUT:
                return
            self._selecting = False
            self._terminal.unselect_all()
            data = bytes(self._held_output)
            self._held_output.clear()
        self._feed_output(data)

    def _feed_output(self, data: bytes) -> None:
        self._has_output = True
        if self._enable_osc52:
            clean_data = self._osc52_parser.feed(data)
            if clean_data:
                self._terminal.feed(clean_data)
        else:
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
                    # Detect Ctrl+D (EOF) to potentially auto-close tab on exit
                    if b"\x04" in data:
                        self._last_eof_time = time.time()
                        
                    # logger.info(f"TerminalTab: Captured User Input: {data!r}")
                    if self._session_bridge and not self._read_only:
                        self._session_bridge.write(data)
            except (OSError, Exception) as e:
                logger.error(f"TerminalTab: PTY read error: {e}")
                return False
        return True
            
    def _on_vte_resize_property(self, *args: Any) -> None:
        """Handler for resize events (from DrawingArea sensor). Uses debouncing."""
        if self._vte_resize_timer_id:
            GLib.source_remove(self._vte_resize_timer_id)
            self._vte_resize_timer_id = 0

        # Debounce for 100ms
        self._vte_resize_timer_id = GLib.timeout_add(100, self._do_vte_resize)

    def _do_vte_resize(self) -> bool:
        self._vte_resize_timer_id = 0
        
        terminal = self._terminal
        cols, rows = terminal.get_column_count(), terminal.get_row_count()
        width, height = terminal.get_width(), terminal.get_height()
        
        logger.info(f"TerminalTab: Resize Event - Pixels: {width}x{height}, Grid: {cols}x{rows}, Remote: {self.is_remote}")
        
        if self._session_bridge:
            if cols > 0 and rows > 0:
                logger.info(f"TerminalTab: Syncing remote PTY to {cols}x{rows}")
                self._session_bridge.resize(cols, rows)
        return False

    def _on_remote_exited(self, exit_status: int) -> None:
        self._set_status(_("Exited with code {exit_status}").format(exit_status=exit_status), persistent=True)
        self._handle_session_exit()

    # ── Local Process ──────────────────────────────────────────

    def _start_local_session(self) -> None:
        """Start a local shell session using the PTY bridge."""
        if not self._ssh_command:
            logger.error("TerminalTab: No command defined for local shell")
            return

        self._set_status(_("Spawning local shell..."), persistent=False)

        ui_callbacks = {
            "on_connected": self._on_remote_connected,
            "on_error": self._on_remote_error
        }
        
        coro = self._ssh_service.start_local_session(
            self._ssh_command,
            ui_callbacks,
            self._on_remote_output,
            self._on_remote_exited
        )
        self._bg_task = self._ssh_service.engine.run_coroutine(coro)

    def _on_local_child_exited(self, terminal: Vte.Terminal, exit_status: int) -> None:
        self._child_pid = None
        self._set_status(_("Exited code {exit_status}").format(exit_status=exit_status >> 8), persistent=True)
        self._handle_session_exit()
        
    def _handle_session_exit(self) -> None:
        """Shared logic to decide between closing or showing reconnect prompt."""
        self._session_bridge = None
        
        # If user pressed Ctrl+D within the last 1 second, close the tab directly
        if time.time() - self._last_eof_time < 1.0:
            logger.info("TerminalTab: User initiated EOF (Ctrl+D), closing tab.")
            self.request_close()
        else:
            if not self._status_persistent:
                self._set_status(_("Disconnected"), persistent=True)
            self._show_reconnect_prompt()

    # ── Shared ────────────────────────────────────────────────

    def _print_terminal_error(self, msg: str) -> None:
        self._terminal.feed(f"\r\n\033[1;31m{msg}\033[0m\r\n".encode("utf-8"))
        
    def _show_reconnect_prompt(self) -> None:
        if self._reconnect_sid:
            return
        self._terminal.feed(b"\r\n\033[1;33m[Session ended. Press Enter to reconnect, or Ctrl+D to close this tab.]\033[0m\r\n")
        self._reconnect_sid = self._terminal.connect("commit", self._on_reconnect_key)

    def _on_reconnect_key(self, terminal: Vte.Terminal, text: str, size: int) -> None:
        if "\x04" in text:
            if self._reconnect_sid:
                terminal.disconnect(self._reconnect_sid)
                self._reconnect_sid = 0
            self.request_close()
        elif "\r" in text or "\n" in text:
            if self._reconnect_sid:
                terminal.disconnect(self._reconnect_sid)
                self._reconnect_sid = 0
            self._set_status(_("Reconnecting…"), persistent=False)
            # Reset terminal state (exit alternate screen, show cursor, reset formatting) without clearing screen/history
            self._terminal.feed(b"\033[?1049l\033[?25h\033[0m")
            self._terminal.feed(f"\r\n\033[1;32m[{_('Reconnecting…')}]\033[0m\r\n".encode("utf-8"))
            if self.is_remote:
                self._connect_remote()
            else:
                self._start_local_session()

    def _on_title_changed(self, terminal: Vte.Terminal) -> None:
        pass

    def _suspend_follow(self) -> None:
        """Stop following output (user is scrolling back or selecting text)."""
        self._terminal.set_scroll_on_output(False)

    def _on_user_scroll(self, controller: Gtk.EventControllerScroll, dx: float, dy: float) -> bool:
        """Wheel/touchpad scrolling up means the user wants to read history."""
        if dy < 0:
            self._suspend_follow()
        return False

    def _on_scroll_value_changed(self, adjustment: Gtk.Adjustment) -> None:
        # Only re-enable following once the view is back at the bottom and no
        # selection is active. Never disable here: programmatic scrolling
        # (e.g. TUIs redrawing many lines) also triggers this signal.
        if self._terminal.get_has_selection():
            return
        distance_to_bottom = (
            adjustment.get_upper() - adjustment.get_page_size() - adjustment.get_value()
        )
        if distance_to_bottom <= 1.0:
            self._terminal.set_scroll_on_output(True)

    def _build_context_menu_model(self, link_uri: str | None = None) -> Gio.Menu:
        """Create a context menu model, optionally inserting link actions at the top."""
        menu = Gio.Menu()

        if link_uri and self._enable_hyperlinks:
            section_link = Gio.Menu()
            section_link.append(_("Open Link"), "term.open-link")
            section_link.append(_("Copy Link Address"), "term.copy-link-address")
            menu.append_section(None, section_link)

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

        return menu

    def _setup_context_menu(self) -> None:
        """Create a right-click context menu for the terminal."""
        menu = self._build_context_menu_model()

        self._popover = Gtk.PopoverMenu.new_from_model(menu)
        self._popover.set_parent(self._terminal)
        self._popover.set_has_arrow(False)

        action_group = Gio.SimpleActionGroup()

        open_link_action = Gio.SimpleAction.new("open-link", None)
        open_link_action.connect("activate", lambda *_: self._open_uri(self._context_uri) if self._context_uri else None)
        action_group.add_action(open_link_action)

        copy_link_action = Gio.SimpleAction.new("copy-link-address", None)
        copy_link_action.connect("activate", lambda *_: self._copy_link_address(self._context_uri) if self._context_uri else None)
        action_group.add_action(copy_link_action)

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
        find_action.connect("activate", lambda *_: self._set_search_visible(True))
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
        self._context_uri = self._get_uri_at_position(x, y) if self._enable_hyperlinks else None
        menu = self._build_context_menu_model(self._context_uri)
        self._popover.set_menu_model(menu)

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
        except Exception:
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
        self._osc52_parser.reset()
        self._held_output.clear()
        self._selecting = False
        if hasattr(self, "_scroll_handler_id") and self._scroll_handler_id:
            try:
                vadjust = self._terminal.get_vadjustment()
                if vadjust:
                    vadjust.disconnect(self._scroll_handler_id)
            except Exception:
                pass
            self._scroll_handler_id = 0

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
            except OSError: pass

        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()
            
        if self._child_pid is not None:
            import signal
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

        # Setup context menu for tabs
        self._setup_context_menu()

    @property
    def widget(self) -> Gtk.Widget:
        return self._root

    @property
    def tab_view(self) -> Adw.TabView:
        return self._tab_view

    @property
    def has_tabs(self) -> bool:
        return self._tab_view.get_n_pages() > 0
    def open_ssh_tab(self, connection: Connection, on_os_detected: Callable | None = None) -> Any:
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

    def open_port_forwarding_tab(self) -> Any:
        """Open the Port Forwarding Management tab, or focus it if already open."""
        from views.port_forwarding_view import PortForwardingTab

        # Check if already open
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            if isinstance(child, PortForwardingTab):
                self._tab_view.set_selected_page(page)
                return child

        # Not open, create new
        pf_tab = PortForwardingTab(self._ssh_service)
        page = self._tab_view.append(pf_tab)
        pf_tab._on_close = lambda t=pf_tab: self._close_specific_tab_by_widget(t)

        page.set_title(pf_tab.title)
        page.set_icon(Gio.ThemedIcon.new("network-transmit-receive-symbolic"))

        self._tab_view.set_selected_page(page)
        return pf_tab

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
        
        # _tabs is deprecated for direct lookup

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
        
        # Rewire close handler to point to this new view
        if hasattr(child, "_on_close"):
            child._on_close = lambda t=child: self._close_specific_tab_by_widget(t)

    def _on_page_detached(self, tab_view: Adw.TabView, page: Adw.TabPage, position: int) -> None:
        """When a page is transferred out of this view."""
        pass

    def notify_connection_updated(self, connection: Connection) -> None:
        """Update any open tabs that are using this connection."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            
            # Check for terminal or sftp connection
            conn_obj = None
            if hasattr(child, "_connection"): # TerminalTab
                conn_obj = child._connection
            elif hasattr(child, "_conn"):     # SftpTab
                conn_obj = child._conn
                
            if conn_obj and conn_obj.id == connection.id:
                logger.info(f"TerminalTabView: Syncing open tab for connection {connection.id}")
                conn_obj.os_id = connection.os_id
                conn_obj.name = connection.name
                conn_obj.hostname = connection.hostname
                conn_obj.username = connection.username
                conn_obj.port = connection.port
                
                # Update page title
                if hasattr(child, "title"):
                    page.set_title(child.title)
                
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

    def find_sftp_service(self, connection_id: str) -> Any | None:
        """Find an active SftpService instance for a connection."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            if child.__class__.__name__ == "SftpTab":
                if hasattr(child, "_conn") and child._conn.id == connection_id:
                    return child._backend
        return None

    def refresh_theme(self) -> None:
        """Refresh theme for all open terminal tabs."""
        # Invalidate cache
        get_terminal_theme(force_refresh=True)

        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            if hasattr(child, "_apply_theme"):
                child._apply_theme()

    def refresh_config(self) -> None:
        """Refresh basic terminal configuration for all open terminal tabs."""
        get_terminal_config(force_refresh=True)

        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            child = page.get_child()
            if hasattr(child, "apply_terminal_config"):
                child.apply_terminal_config()

    def _setup_context_menu(self) -> None:
        """Create and bind the context menu and action group to the tab view."""
        self._tab_menu = Gio.Menu()
        self._tab_view.set_menu_model(self._tab_menu)

        action_group = Gio.SimpleActionGroup()

        duplicate_action = Gio.SimpleAction.new("duplicate", None)
        duplicate_action.connect("activate", self._on_duplicate_activate)
        action_group.add_action(duplicate_action)

        duplicate_nw_action = Gio.SimpleAction.new("duplicate-new-window", None)
        duplicate_nw_action.connect("activate", self._on_duplicate_nw_activate)
        action_group.add_action(duplicate_nw_action)

        open_sftp_action = Gio.SimpleAction.new("open-sftp", None)
        open_sftp_action.connect("activate", self._on_open_sftp_activate)
        action_group.add_action(open_sftp_action)

        open_ssh_action = Gio.SimpleAction.new("open-ssh", None)
        open_ssh_action.connect("activate", self._on_open_ssh_activate)
        action_group.add_action(open_ssh_action)

        self._tab_view.insert_action_group("tab", action_group)
        self._tab_actions = action_group

        self._tab_view.connect("setup-menu", self._on_setup_menu)
        self._context_menu_page = None

    def _on_setup_menu(self, tab_view: Adw.TabView, page: Adw.TabPage | None) -> None:
        """Callback triggered when the tab context menu is about to be displayed."""
        if page is None:
            return

        logger.info(f"Tab context menu triggered for page: {page.get_title()}")

        self._context_menu_page = page

        # Dynamically register the action group onto the root window to ensure Popover can find actions
        root_window = self._root.get_root()
        if root_window:
            root_window.insert_action_group("tab", self._tab_actions)

        # Clear and dynamically rebuild the menu
        self._tab_menu.remove_all()
        self._tab_menu.append(_("Duplicate"), "tab.duplicate")
        self._tab_menu.append(_("Duplicate in a new window"), "tab.duplicate-new-window")

        child = page.get_child()
        is_supported = child.__class__.__name__ in ("TerminalTab", "SftpTab")

        dup_act = self._tab_actions.lookup_action("duplicate")
        if dup_act:
            dup_act.set_enabled(is_supported)

        dup_nw_act = self._tab_actions.lookup_action("duplicate-new-window")
        if dup_nw_act:
            dup_nw_act.set_enabled(is_supported)

        # Add SFTP or Shell options dynamically based on the current tab type
        if child.__class__.__name__ == "TerminalTab":
            if child.connection is not None:
                self._tab_menu.append(_("SFTP"), "tab.open-sftp")
        elif child.__class__.__name__ == "SftpTab":
            self._tab_menu.append(_("Shell"), "tab.open-ssh")

    def _on_duplicate_activate(self, action: Gio.SimpleAction, parameter: GLib.Variant | None) -> None:
        if self._context_menu_page:
            self._duplicate_page(self._context_menu_page)

    def _on_duplicate_nw_activate(self, action: Gio.SimpleAction, parameter: GLib.Variant | None) -> None:
        if self._context_menu_page:
            self._duplicate_page_to_new_window(self._context_menu_page)

    def _on_open_sftp_activate(self, action: Gio.SimpleAction, parameter: GLib.Variant | None) -> None:
        if self._context_menu_page:
            child = self._context_menu_page.get_child()
            if child.__class__.__name__ == "TerminalTab" and child.connection:
                self.open_sftp_tab(child.connection)

    def _on_open_ssh_activate(self, action: Gio.SimpleAction, parameter: GLib.Variant | None) -> None:
        if self._context_menu_page:
            child = self._context_menu_page.get_child()
            if child.__class__.__name__ == "SftpTab" and child.connection:
                self.open_ssh_tab(child.connection)

    def _duplicate_page(self, page: Adw.TabPage) -> None:
        child = page.get_child()
        if child.__class__.__name__ == "TerminalTab":
            if child.connection:
                self.open_ssh_tab(child.connection)
            else:
                self.open_local_tab()
        elif child.__class__.__name__ == "SftpTab":
            conn = getattr(child, "_conn", None) or getattr(child, "_connection", None)
            if conn:
                self.open_sftp_tab(conn)

    def _duplicate_page_to_new_window(self, page: Adw.TabPage) -> None:
        from views.main_window import SentinelWindow
        app = Gio.Application.get_default()
        if not app:
            return

        new_window = SentinelWindow(application=app)
        new_window.present()
        new_window._content_stack.set_visible_child_name("terminals")

        child = page.get_child()
        if child.__class__.__name__ == "TerminalTab":
            if child.connection:
                new_window._terminal_tab_view.open_ssh_tab(child.connection)
            else:
                new_window._terminal_tab_view.open_local_tab()
        elif child.__class__.__name__ == "SftpTab":
            conn = getattr(child, "_conn", None) or getattr(child, "_connection", None)
            if conn:
                new_window._terminal_tab_view.open_sftp_tab(conn)
