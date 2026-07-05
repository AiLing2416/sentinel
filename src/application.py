# SPDX-License-Identifier: GPL-3.0-or-later

"""Sentinel Adw.Application — manages app lifecycle, actions, and CSS."""

from __future__ import annotations

import gi
import logging
import re

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

class SentinelLogFilter(logging.Filter):
    """Smart Filter to redact sensitive metadata in Sentinel logs (IPs, emails, domains, names, IDs)."""

    def __init__(self, name: str = ""):
        super().__init__(name)
        # 1. IP regular expression (Captures first two octets)
        self._ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b')
        
        # 2. Email regular expression
        self._email_re = re.compile(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,4})\b')
        
        # 3. Independent Domain regular expression (Exclude IP addresses, match xxx.yyy.com)
        self._domain_re = re.compile(r'\b(?:[A-Za-z0-9-]+\.)+([A-Za-z0-9-]+\.[A-Za-z]{2,4})\b')
        
        # 4. UUID regular expression (Hide middle parts of 36-char UUIDs)
        self._uuid_re = re.compile(r'\b([0-9a-fA-F]{4})[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{8}([0-9a-fA-F]{4})\b')
        
        # 5. Quoted values (e.g. 'Connection Name' or "Item ID")
        self._quoted_re = re.compile(r"'(?P<val1>[^']+)'|\"(?P<val2>[^\"]+)\"")
        
        # 6. Keyword-based ID detection (e.g. rule rule_12345 or connection conn_abc)
        self._kw_id_re = re.compile(r'\b(rule|connection|item|folder|vault)\s+([a-zA-Z0-9_-]+)\b', re.IGNORECASE)
        
        # 7. Local home paths
        self._home_path_re = re.compile(r'/home/[^/ ]+/')

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)
        if record.args:
            record.args = tuple(
                self._redact(arg) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True

    def _redact(self, text: str) -> str:
        # Step 1: Redact IP (Show first two octets)
        text = self._ip_re.sub(r'\1.*.*', text)
        
        # Step 2: Redact Emails (Show only domain TLD)
        def redact_email(match):
            domain = match.group(2)
            parts = domain.split('.')
            tld = parts[-1]
            if len(parts) >= 2 and parts[-2] in ('co', 'org', 'gov', 'com', 'net', 'edu', 'ac'):
                tld = f"{parts[-2]}.{tld}"
            return f"*@*.{tld}"
        text = self._email_re.sub(redact_email, text)
        
        # Step 3: Redact independent domains (Show only TLD)
        def redact_domain(match):
            domain = match.group(1)
            parts = domain.split('.')
            tld = parts[-1]
            if len(parts) >= 2 and parts[-2] in ('co', 'org', 'gov', 'com', 'net', 'edu', 'ac'):
                tld = f"{parts[-2]}.{tld}"
            return f"***.{tld}"
        
        def domain_sub(match):
            full_match = match.group(0)
            # Skip python typical package paths to avoid false positives in code loading logs
            if any(pkg in full_match for pkg in ('gi.repository', 'db.database', 'services.', 'views.', 'models.')):
                return full_match
            return redact_domain(match)
        text = self._domain_re.sub(domain_sub, text)

        # Step 4: Redact UUIDs
        text = self._uuid_re.sub(r'\1...\2', text)
        
        # Step 5: Redact Quoted names/IDs (Hide middle parts)
        state_words = {
            'locked', 'unlocked', 'unauthenticated', 'authenticated', 
            'true', 'false', 'none', 'null', 'active', 'inactive', 'success', 'failed',
            'connected', 'disconnected', 'connecting', 'error'
        }
        def redact_quoted(match):
            quote = "'" if match.group('val1') is not None else '"'
            val = match.group('val1') if match.group('val1') is not None else match.group('val2')
            if val.lower() in state_words:
                return f"{quote}{val}{quote}"
            if len(val) > 4:
                half = max(1, len(val) // 4)
                return f"{quote}{val[:half]}...{val[-half:]}{quote}"
            return f"{quote}{val}{quote}"
        text = self._quoted_re.sub(redact_quoted, text)
        
        # Step 6: Redact Keyword-based IDs
        def redact_kw_id(match):
            kw = match.group(1)
            val = match.group(2)
            # Skip common short words or status codes
            if len(val) > 4 and val.lower() not in ('started', 'stopped', 'failed', 'active', 'error'):
                half = max(1, len(val) // 4)
                return f"{kw} {val[:half]}...{val[-half:]}"
            return match.group(0)
        text = self._kw_id_re.sub(redact_kw_id, text)
        
        # Step 7: Redact local home paths
        text = self._home_path_re.sub("/home/[REDACTED_USER]/", text)
        
        return text



_ = gettext.gettext


class SentinelApplication(Adw.Application):
    """Main application class for Sentinel."""

    def __init__(self) -> None:
        # Apply log filter to hide sensitive metadata
        log_filter = SentinelLogFilter()
        for handler in logging.root.handlers:
            handler.addFilter(log_filter)

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
            version="0.3.0",
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

        /* ── FlowBox Cards Hover/Selection fixes ── */
        .host-card {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .key-card {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .host-card:hover {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .key-card:hover {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .host-card:selected {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .key-card:selected {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .host-card:focus {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .key-card:focus {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }

        /* Hover card style */
        .host-card:hover .card,
        .key-card:hover .card {
            background-image: linear-gradient(
                to bottom,
                alpha(currentColor, 0.04),
                alpha(currentColor, 0.04)
            );
        }

        /* Selected card style */
        .host-card:selected .card,
        .key-card:selected .card {
            box-shadow: inset 0 0 0 2px @accent_color;
            background-image: linear-gradient(
                to bottom,
                alpha(@accent_color, 0.08),
                alpha(@accent_color, 0.08)
            );
        }
        .host-card:selected:hover .card,
        .key-card:selected:hover .card {
            box-shadow: inset 0 0 0 2px @accent_color;
            background-image: linear-gradient(
                to bottom,
                alpha(@accent_color, 0.12),
                alpha(@accent_color, 0.12)
            );
        }

        /* Micro-animation transitions for smooth hover/selection state */
        .card {
            transition: box-shadow 150ms ease, background-image 150ms ease;
        }

        /* ═══════════════════════════════════════════════
         *  NEW REDESIGN STYLES
         * ═══════════════════════════════════════════════ */

        /* ── Sidebar Navigation (pill style) ──────────── */
        .nav-section-label {
            font-size: 0.70em;
            font-weight: 600;
            letter-spacing: 0.08em;
            color: alpha(@sidebar_fg_color, 0.42);
            padding: 14px 16px 4px 16px;
        }
        /* nav-item is a Gtk.Button — override flat button defaults */
        .nav-item {
            border-radius: 999px;
            padding: 7px 12px;
            margin: 1px 8px;
            transition: all 250ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
            color: @sidebar_fg_color;
            box-shadow: none;
            border: none;
            outline: none;
        }
        .nav-item:hover {
            background-color: alpha(@sidebar_fg_color, 0.07);
            box-shadow: none;
        }
        .nav-item.selected {
            background-color: alpha(@accent_color, 0.14);
            color: @accent_color;
            font-weight: bold;
            box-shadow: none;
        }
        .nav-item:active {
            box-shadow: none;
        }

        /* ── Collapsed rail: 36x36 circular buttons (sidebar is 52px wide) ── */
        .nav-collapsed-item {
            padding: 9px !important;
            margin: 1px 8px !important;
            border-radius: 999px !important;
            min-width: 36px !important;
            min-height: 36px !important;
        }

        /* Sidebar header/footer CenterBox */
        .sidebar-header-box {
            background-color: @headerbar_bg_color;
            border-bottom: 1px solid @borders;
            min-height: 47px;
        }
        .sidebar-bottom-bar {
            border-top: 1px solid @borders;
            padding: 4px 8px;
        }

        .sidebar-action-btn {
            transition: margin-left 250ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }
        .sidebar-action-btn.header-expanded { margin-left: 13px; }
        .sidebar-action-btn.header-collapsed { margin-left: 10px; }
        .sidebar-action-btn.footer-expanded { margin-left: 5px; }
        .sidebar-action-btn.footer-collapsed { margin-left: 2px; }

        /* ── Host Card (redesigned) ────────────────────── */
        .host-card-v2 {
            border-radius: 12px;
            background-color: @card_bg_color;
            border: 1px solid @card_shade_color;
            transition: box-shadow 150ms ease;
            box-shadow: 0 1px 3px alpha(black, 0.06);
        }
        .host-card-v2:hover {
            box-shadow: 0 3px 8px alpha(black, 0.12);
        }
        .host-card-v2.selected {
            border-color: @accent_color;
            box-shadow: 0 0 0 2px alpha(@accent_color, 0.3);
        }

        /* Auth type accent stripe (integrated as top 4px background on host card) */
        .host-card-v2.auth-stripe-key,
        .host-card-v2.auth-stripe-password,
        .host-card-v2.auth-stripe-agent,
        .host-card-v2.auth-stripe-vault,
        .host-card-v2.auth-stripe-key_passphrase {
            border-top-color: transparent;
            background-size: 100% 4px;
            background-repeat: no-repeat;
            background-position: top left;
        }
        .host-card-v2.auth-stripe-key {
            background-image: linear-gradient(90deg, @blue_3, @blue_4);
        }
        .host-card-v2.auth-stripe-password {
            background-image: linear-gradient(90deg, @orange_3, @orange_4);
        }
        .host-card-v2.auth-stripe-agent {
            background-image: linear-gradient(90deg, @green_3, @green_4);
        }
        .host-card-v2.auth-stripe-vault {
            background-image: linear-gradient(90deg, @purple_3, @purple_4);
        }
        .host-card-v2.auth-stripe-key_passphrase {
            background-image: linear-gradient(90deg, @blue_3, @purple_3);
        }

        /* Port Forwarding status bars integrated as top 4px background on host card */
        .host-card-v2.forward-stripe-running,
        .host-card-v2.forward-stripe-stopped,
        .host-card-v2.forward-stripe-error,
        .host-card-v2.forward-stripe-connecting {
            border-top-color: transparent;
            background-size: 100% 4px;
            background-repeat: no-repeat;
            background-position: top left;
        }
        .host-card-v2.forward-stripe-running {
            background-image: linear-gradient(90deg, @success_color, @success_color);
        }
        .host-card-v2.forward-stripe-stopped {
            background-image: linear-gradient(90deg, alpha(@dim_label_color, 0.28), alpha(@dim_label_color, 0.28));
        }
        .host-card-v2.forward-stripe-error {
            background-image: linear-gradient(90deg, @error_color, @error_color);
        }
        .host-card-v2.forward-stripe-connecting {
            background-image: linear-gradient(90deg, @warning_color, @warning_color);
        }

        /* Keychain key type accents integrated as top 4px background on host card */
        .host-card-v2.key-stripe-ed25519,
        .host-card-v2.key-stripe-rsa,
        .host-card-v2.key-stripe-ecdsa,
        .host-card-v2.key-stripe-default {
            border-top-color: transparent;
            background-size: 100% 4px;
            background-repeat: no-repeat;
            background-position: top left;
        }
        .host-card-v2.key-stripe-ed25519 {
            background-image: linear-gradient(90deg, @blue_3, @blue_4);
        }
        .host-card-v2.key-stripe-rsa {
            background-image: linear-gradient(90deg, @green_3, @green_4);
        }
        .host-card-v2.key-stripe-ecdsa {
            background-image: linear-gradient(90deg, @purple_3, @purple_4);
        }
        .host-card-v2.key-stripe-default {
            background-image: linear-gradient(90deg, @accent_color, @accent_color);
        }

        /* Auth badge (small pill in card corner) */
        .auth-badge {
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 0.70em;
            font-weight: 600;
            background-color: alpha(@accent_color, 0.12);
            color: @accent_color;
        }

        /* ── Key Card (redesigned) ─────────────────────── */
        /* Left accent stripe for key type */
        .key-accent-ed25519 {
            background-color: @blue_4;
            border-radius: 12px 0 0 12px;
            min-width: 4px;
        }
        .key-accent-rsa {
            background-color: @green_4;
            border-radius: 12px 0 0 12px;
            min-width: 4px;
        }
        .key-accent-ecdsa {
            background-color: @purple_4;
            border-radius: 12px 0 0 12px;
            min-width: 4px;
        }
        .key-accent-default {
            background-color: @accent_color;
            border-radius: 12px 0 0 12px;
            min-width: 4px;
        }

        /* Key type badge */
        .key-type-badge {
            border-radius: 5px;
            padding: 2px 7px;
            font-size: 0.70em;
            font-weight: 700;
            letter-spacing: 0.04em;
        }
        .key-type-badge.ed25519 {
            background-color: alpha(@blue_3, 0.15);
            color: @blue_4;
        }
        .key-type-badge.rsa {
            background-color: alpha(@green_3, 0.15);
            color: @green_5;
        }
        .key-type-badge.ecdsa {
            background-color: alpha(@purple_3, 0.15);
            color: @purple_4;
        }
        .key-type-badge.other {
            background-color: alpha(@accent_color, 0.12);
            color: @accent_color;
        }

        /* Fingerprint monospace label */
        .fingerprint-label {
            font-family: monospace;
            font-size: 0.76em;
            background-color: alpha(@card_shade_color, 0.7);
            border-radius: 5px;
            padding: 3px 7px;
        }

        /* ── Port Forwarding Rule Card ──────────────────── */
        .forward-card {
            background: transparent;
            background-color: transparent;
            background-image: none;
            box-shadow: none;
            outline: none;
            border: none;
        }
        .forward-card:hover .host-card-v2 {
            background-image: linear-gradient(
                to bottom,
                alpha(currentColor, 0.04),
                alpha(currentColor, 0.04)
            );
        }
        .forward-card:selected .host-card-v2 {
            box-shadow: inset 0 0 0 2px @accent_color;
            background-image: linear-gradient(
                to bottom,
                alpha(@accent_color, 0.08),
                alpha(@accent_color, 0.08)
            );
        }
        .forward-card:selected:hover .host-card-v2 {
            box-shadow: inset 0 0 0 2px @accent_color;
            background-image: linear-gradient(
                to bottom,
                alpha(@accent_color, 0.12),
                alpha(@accent_color, 0.12)
            );
        }

        /* ── Port Forwarding Rule Row ───────────────────── */
        .forward-rule-row {
            border-radius: 10px;
            background-color: @card_bg_color;
            border: 1px solid @card_shade_color;
            margin: 3px 0;
        }
        /* Status indicator left bars */
        .status-bar-running {
            background-color: @success_color;
            border-radius: 9px 0 0 9px;
            min-width: 4px;
        }
        .status-bar-stopped {
            background-color: alpha(@dim_label_color, 0.28);
            border-radius: 9px 0 0 9px;
            min-width: 4px;
        }
        .status-bar-error {
            background-color: @error_color;
            border-radius: 9px 0 0 9px;
            min-width: 4px;
        }
        .status-bar-connecting {
            background-color: @warning_color;
            border-radius: 9px 0 0 9px;
            min-width: 4px;
        }
        /* Forward type badge */
        .forward-type-badge {
            border-radius: 5px;
            padding: 2px 7px;
            font-size: 0.70em;
            font-weight: 700;
        }
        .forward-type-local {
            background-color: alpha(@blue_3, 0.15);
            color: @blue_4;
        }
        .forward-type-remote {
            background-color: alpha(@orange_3, 0.15);
            color: @orange_4;
        }
        .forward-type-dynamic {
            background-color: alpha(@purple_3, 0.15);
            color: @purple_4;
        }

        /* ── Right Detail Panel ────────────────────────── */
        .detail-panel {
            background-color: @card_bg_color;
            border-left: 1px solid @borders;
        }

        /* ── Unlock Screen Card ────────────────────────── */
        .unlock-card {
            border-radius: 16px;
            background-color: @card_bg_color;
            border: 1px solid alpha(@borders, 0.6);
            box-shadow: 0 4px 20px alpha(black, 0.10), 0 1px 4px alpha(black, 0.06);
        }

        /* ── Entry Placeholder Fix ─────────────────────── */
        entry text placeholder,
        text placeholder,
        placeholder {
            font-size: 15px;
            margin: 0;
            padding: 0;
            opacity: 0.55;
        }
        """
