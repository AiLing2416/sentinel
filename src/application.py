# SPDX-License-Identifier: GPL-3.0-or-later

"""Sentinel Adw.Application — manages app lifecycle, actions, and CSS."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

_ = gettext.gettext


class SentinelApplication(Adw.Application):
    """Main application class for Sentinel."""

    def __init__(self) -> None:
        super().__init__(
            application_id="io.github.ailing2416.sentinel",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )

        self._setup_actions()

    # ── Lifecycle ─────────────────────────────────────────────
    def do_activate(self) -> None:
        win = self.props.active_window
        if not win:
            from views.main_window import SentinelWindow

            win = SentinelWindow(application=self)
        win.present()

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_css()

    # ── Actions ───────────────────────────────────────────────
    def _setup_actions(self) -> None:
        """Register application-wide actions."""
        actions = [
            ("quit", self._on_quit, ["<primary>q"]),
            ("about", self._on_about, None),
            ("new-connection", self._on_new_connection, ["<primary>n"]),
            ("app_settings", self._on_app_settings, None),
            ("vault_settings", self._on_vault_settings, None),
            ("terminal_theme", self._on_terminal_theme, None),
        ]
        for name, callback, accels in actions:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            if accels:
                self.set_accels_for_action(f"app.{name}", accels)

    def _on_quit(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        self.quit()

    def _on_about(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        about = Adw.AboutDialog(
            application_name=_("Sentinel"),
            application_icon="utilities-terminal",
            developer_name=_("Sentinel Contributors"),
            version="0.2.2",
            developers=[_("Sentinel Contributors")],
            copyright=_("© 2026 Sentinel Contributors"),
            license_type=Gtk.License.GPL_3_0,
            comments=_("A secure GNOME SSH connection manager\nwith password manager integration."),
            website="https://github.com/AiLing2416/sentinel",
        )
        about.present(self.props.active_window)

    def _on_new_connection(
        self, _action: Gio.SimpleAction, _param: GLib.Variant | None
    ) -> None:
        win = self.props.active_window
        if win and hasattr(win, "show_connection_editor"):
            win.show_connection_editor()

    def _on_app_settings(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        from views.app_settings_dialog import AppSettingsWindow
        win = self.props.active_window
        settings_win = AppSettingsWindow(app=self)
        settings_win.set_transient_for(win)
        settings_win.set_modal(False)
        settings_win.present()

    def _on_vault_settings(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        from views.vault_settings_dialog import VaultManagerWindow
        win = self.props.active_window
        vault_win = VaultManagerWindow(app=self)
        vault_win.set_transient_for(win)
        vault_win.set_modal(False)  # Non-modal: user can still use the main window
        vault_win.present()

    def _on_terminal_theme(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        import logging
        logger = logging.getLogger(__name__)
        try:
            from views.terminal_theme_dialog import TerminalThemeWindow
            win = self.props.active_window
            logger.info("Opening Terminal Theme window...")
            theme_win = TerminalThemeWindow(app=self)
            theme_win.set_transient_for(win)
            theme_win.set_modal(False)
            theme_win.present()
        except Exception as e:
            logger.error(f"Failed to open Terminal Theme window: {e}", exc_info=True)

    # ── CSS ───────────────────────────────────────────────────
    def _load_css(self) -> None:
        """Load custom CSS styling."""
        import gi
        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk

        css_provider = Gtk.CssProvider()
        css_provider.load_from_string(self._get_css())
        display = Gdk.Display.get_default()
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display,
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )

    @staticmethod
    def _get_css() -> str:
        return """
        /* ── Connection list ────────────────────────── */
        .connection-list {
            background: transparent;
        }
        .connection-row {
            padding: 2px 4px;
        }
        .connection-row .host-label {
            font-size: 0.85em;
            opacity: 0.6;
        }
        .os-icon-box {
            min-width: 32px;
            min-height: 32px;
            color: @accent_color;
        }

        /* ── Welcome page ───────────────────────────── */
        .welcome-icon {
            opacity: 0.15;
            margin-bottom: 12px;
        }
        .welcome-title {
            font-size: 1.6em;
            font-weight: 800;
            opacity: 0.8;
        }
        .welcome-subtitle {
            font-size: 1em;
            opacity: 0.5;
        }
        .empty-sidebar-title {
            font-weight: 700;
            font-size: 1.1em;
            opacity: 0.7;
        }
        .empty-sidebar-subtitle {
            opacity: 0.45;
            font-size: 0.9em;
        }
        .group-header {
            font-size: 0.75em;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            opacity: 0.45;
            padding: 12px 18px 4px;
        }
        .editor-page {
            margin: 0 12px;
        }

        /* ─────────────────────────────────────────────
         *  Chromium-style Tab Bar
         * ───────────────────────────────────────────── */

        /* Header strip containing tabs + drag area + window controls */
        .chrome-header {
            min-height: 38px;
            padding: 0;
            background: alpha(@headerbar_bg_color, 0.95);
            border-bottom: 1px solid alpha(@borders, 0.3);
        }

        /* Tab bar container */
        .chrome-tab-bar {
            padding: 4px 0 0 6px;
            min-height: 34px;
        }

        /* Inner box holding tab buttons — spacing set via Gtk.Box */

        /* ── Individual Tab ────────────────────────── */
        .chrome-tab {
            min-height: 30px;
            min-width: 48px;
            padding: 0 8px;
            margin: 0 1px;
            border-radius: 8px 8px 0 0;
            background: alpha(@card_bg_color, 0.0);
            border: 1px solid transparent;
            border-bottom: none;
            transition: background-color 150ms ease,
                        border-color    150ms ease,
                        box-shadow      150ms ease;
        }
        .chrome-tab:hover {
            background: alpha(@card_bg_color, 0.45);
        }

        /* Active / selected tab — raised, opaque, with subtle shadow */
        .chrome-tab.active {
            background: alpha(@card_bg_color, 0.85);
            border-color: alpha(@borders, 0.2);
            box-shadow: 0 -1px 3px alpha(black, 0.08);
        }

        /* Tab icon */
        .chrome-tab-icon {
            opacity: 0.7;
            min-width: 16px;
            min-height: 16px;
        }
        .chrome-tab.active .chrome-tab-icon {
            opacity: 1.0;
        }

        /* Tab label */
        .chrome-tab-label {
            font-size: 0.82em;
            font-weight: 500;
            opacity: 0.65;
        }
        .chrome-tab.active .chrome-tab-label {
            opacity: 1.0;
            font-weight: 600;
        }
        .chrome-tab:hover .chrome-tab-label {
            opacity: 0.85;
        }

        /* Close button on each tab */
        .chrome-tab-close {
            min-width: 20px;
            min-height: 20px;
            padding: 0;
            opacity: 0;
            transition: opacity 150ms ease, background-color 150ms ease;
        }
        .chrome-tab:hover .chrome-tab-close,
        .chrome-tab.active .chrome-tab-close {
            opacity: 0.6;
        }
        .chrome-tab .chrome-tab-close:hover {
            opacity: 1.0;
        }

        /* New-tab (+) button */
        .chrome-new-tab {
            min-width: 28px;
            min-height: 28px;
            margin: 3px 4px 0 2px;
            padding: 0;
            opacity: 0.55;
            transition: opacity 150ms ease, background-color 150ms ease;
        }
        .chrome-new-tab:hover {
            opacity: 1.0;
            background-color: alpha(@card_bg_color, 0.45);
        }

        /* Drag spacer (titlebar drag region) */
        .chrome-drag-spacer {
            min-width: 48px;
        }

        /* ── SFTP Browser ───────────────────────────── */
        .sftp-file-list {
            background: @window_bg_color;
        }
        .sftp-file-list row {
            padding: 8px 0;
            border-bottom: 1px solid alpha(@borders, 0.1);
        }
        .sftp-file-list row:hover {
            background: alpha(@accent_color, 0.05);
        }
        .sftp-file-list row:selected {
            background: alpha(@accent_color, 0.15);
            color: @accent_fg_color;
        }
        .toolbar {
            padding: 6px 12px;
            background: alpha(@headerbar_bg_color, 0.5);
            border-bottom: 1px solid alpha(@borders, 0.2);
        }
        .drag-over {
            background: alpha(@accent_color, 0.1);
            box-shadow: inset 0 0 10px alpha(@accent_color, 0.3);
            transition: background 200ms ease-in-out;
        }
        """

