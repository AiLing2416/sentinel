# SPDX-License-Identifier: GPL-3.0-or-later

"""Vault Manager Window — standalone preferences view for Bitwarden integration and Local Vault status."""

from __future__ import annotations

import asyncio
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
from gi.repository import Adw, Gtk, GLib, Pango

_ = gettext.gettext

from services.vault_service import VaultService
from services.vault_manager import VaultManager
from utils.secure import SecureBytes
from db.database import Database
import logging

logger = logging.getLogger(__name__)


class VaultManagerWindow(Gtk.Box):
    """A settings view for managing Bitwarden and Local Vault settings in a single modern preferences page."""

    def __init__(self, app: Adw.Application, on_close_callback: Callable[[], None] | None = None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._app = app
        self._on_close_callback = on_close_callback
        self._vault = VaultService.get().get_backend("bitwarden")
        self._ignore_folder_changes = False
        self._login_pwd: SecureBytes | None = None
        self._login_email: str | None = None

        self._build_ui()
        self._check_status()

    def _build_ui(self) -> None:
        # Toast Overlay is the top-level container of this Box
        self._toast_overlay = Adw.ToastOverlay()
        self.append(self._toast_overlay)

        # Create main stack inside Toast Overlay
        self._main_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=250,
        )
        self._toast_overlay.set_child(self._main_stack)

        # ── Loading Page ──
        self._loading_page = self._build_loading_page()
        self._main_stack.add_named(self._loading_page, "loading")

        # ── Content Page ──
        content_scroll = Gtk.ScrolledWindow(vexpand=True)
        
        content_clamp = Adw.Clamp()
        content_clamp.set_maximum_size(680)
        content_scroll.set_child(content_clamp)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        content_box.set_margin_start(16)
        content_box.set_margin_end(16)
        content_box.set_margin_top(24)
        content_box.set_margin_bottom(24)
        content_clamp.set_child(content_box)

        # Register content scroll page to the main stack
        self._main_stack.add_named(content_scroll, "content")

        # Title Label
        title_label = Gtk.Label(label=_("Vault Settings"))
        title_label.add_css_class("title-1")
        title_label.set_halign(Gtk.Align.START)
        title_label.set_margin_bottom(12)
        content_box.append(title_label)

        # ── 1. Local Vault Preferences Group ──
        self._local_group = Adw.PreferencesGroup(
            title=_("Local Vault"),
            description=_("Sentinel automatically manages an encrypted local database to cache your configurations, rules, and keys.")
        )
        
        self._local_status_row = Adw.ActionRow(
            title=_("Status"),
            subtitle=_("Active and Auto-unlocked ✓")
        )
        status_icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
        status_icon.add_css_class("accent")
        self._local_status_row.add_prefix(status_icon)
        self._local_group.add(self._local_status_row)

        self._local_reset_row = Adw.ActionRow(
            title=_("Reset Local Vault"),
            subtitle=_("Permanently erase all connection cache and local keys")
        )
        reset_btn = Gtk.Button(label=_("Reset"))
        reset_btn.set_valign(Gtk.Align.CENTER)
        reset_btn.add_css_class("flat")
        reset_btn.add_css_class("destructive-action")
        reset_btn.connect("clicked", self._on_local_vault_reset_clicked)
        self._local_reset_row.add_suffix(reset_btn)
        self._local_group.add(self._local_reset_row)

        content_box.append(self._local_group)

        # ── 2. Bitwarden Preferences Group ──
        self._bw_group = Adw.PreferencesGroup(
            title=_("Bitwarden Integration"),
            description=_("Sync your SSH keys and passwords from your Bitwarden cloud vault.")
        )
        
        self._bw_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
            transition_duration=250,
        )
        self._bw_group.add(self._bw_stack)
        content_box.append(self._bw_group)

        # Build Sub-pages for Bitwarden Stack
        self._login_subpage = self._build_login_subpage()
        self._bw_stack.add_named(self._login_subpage, "login")

        self._two_factor_subpage = self._build_two_factor_subpage()
        self._bw_stack.add_named(self._two_factor_subpage, "two_factor")

        self._unlock_subpage = self._build_unlock_subpage()
        self._bw_stack.add_named(self._unlock_subpage, "unlock")

        self._settings_subpage = self._build_settings_subpage()
        self._bw_stack.add_named(self._settings_subpage, "settings")

    def _build_loading_page(self) -> Gtk.Widget:
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            spacing=16,
        )
        spinner = Gtk.Spinner(spinning=True)
        spinner.set_size_request(32, 32)
        box.append(spinner)
        label = Gtk.Label(label=_("Checking Vault Status…"))
        label.add_css_class("dim-label")
        box.append(label)
        return box

    def _build_login_subpage(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        
        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        # Server URL
        self._server_entry = Gtk.Entry()
        self._server_entry.set_placeholder_text(_("https://bitwarden.com (leave blank for default)"))
        self._server_entry.set_hexpand(True)
        self._server_entry.set_margin_top(6)
        self._server_entry.set_margin_bottom(6)
        self._server_entry.set_margin_start(12)
        self._server_entry.set_margin_end(12)
        
        srv_row = Adw.ExpanderRow(title=_("Custom Server"), subtitle=_("For self-hosted Bitwarden / VaultWarden"))
        srv_row.add_row(self._server_entry)
        list_box.append(srv_row)

        # Email
        self._email_entry = Adw.EntryRow(title=_("Email Address"))
        list_box.append(self._email_entry)

        # Password
        self._password_row = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._password_row)

        box.append(list_box)

        # Remember Password
        self._login_remember_check = Gtk.CheckButton(label=_("Save master password securely in system keyring"))
        self._login_remember_check.set_active(True)
        self._login_remember_check.set_margin_start(6)
        box.append(self._login_remember_check)

        # Login button
        self._login_btn = Gtk.Button(label=_("Log In"))
        self._login_btn.add_css_class("suggested-action")
        self._login_btn.add_css_class("pill")
        self._login_btn.connect("clicked", self._on_login_clicked)
        self._password_row.connect("entry-activated", self._on_login_clicked)
        box.append(self._login_btn)

        return box

    def _build_two_factor_subpage(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        # Desc label
        self._2fa_desc_label = Gtk.Label(label=_("Your account requires two-step verification."))
        self._2fa_desc_label.set_halign(Gtk.Align.START)
        self._2fa_desc_label.add_css_class("dim-label")
        box.append(self._2fa_desc_label)

        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        self._2fa_method_labels = [
            _("Authenticator App (TOTP)"),
            _("Email"),
            _("YubiKey OTP"),
            _("Duo"),
            _("FIDO2 / WebAuthn (hardware key)"),
        ]
        self._2fa_method_ids = [0, 1, 3, 2, 7]
        self._2fa_method_model = Gtk.StringList.new(self._2fa_method_labels)
        self._2fa_method_row = Adw.ComboRow(
            title=_("Verification Method"),
            model=self._2fa_method_model,
        )
        self._2fa_method_row.connect("notify::selected", self._on_2fa_method_changed)
        list_box.append(self._2fa_method_row)

        self._2fa_code_entry = Adw.EntryRow(title=_("Verification Code"))
        self._2fa_code_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        list_box.append(self._2fa_code_entry)
        box.append(list_box)

        # Hint label
        self._2fa_hint_label = Gtk.Label(xalign=0, wrap=True)
        self._2fa_hint_label.add_css_class("dim-label")
        self._2fa_hint_label.add_css_class("caption")
        box.append(self._2fa_hint_label)

        # Buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        back_btn = Gtk.Button(label=_("Back"))
        back_btn.add_css_class("pill")
        back_btn.set_hexpand(True)
        back_btn.connect("clicked", lambda _: self._bw_stack.set_visible_child_name("login"))
        btn_box.append(back_btn)

        self._2fa_submit_btn = Gtk.Button(label=_("Verify & Log In"))
        self._2fa_submit_btn.add_css_class("suggested-action")
        self._2fa_submit_btn.add_css_class("pill")
        self._2fa_submit_btn.set_hexpand(True)
        self._2fa_submit_btn.connect("clicked", self._on_2fa_submit)
        self._2fa_code_entry.connect("entry-activated", self._on_2fa_submit)
        btn_box.append(self._2fa_submit_btn)

        box.append(btn_box)
        return box

    def _build_unlock_subpage(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        self._unlock_email_row = Adw.ActionRow(title=_("Account"))
        list_box.append(self._unlock_email_row)

        self._unlock_entry = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._unlock_entry)
        box.append(list_box)

        self._unlock_remember_check = Gtk.CheckButton(label=_("Save master password securely in system keyring"))
        self._unlock_remember_check.set_active(True)
        self._unlock_remember_check.set_margin_start(6)
        box.append(self._unlock_remember_check)

        # Buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        
        logout_btn = Gtk.Button(label=_("Log Out"))
        logout_btn.add_css_class("destructive-action")
        logout_btn.add_css_class("pill")
        logout_btn.set_hexpand(True)
        logout_btn.connect("clicked", self._on_logout_clicked)
        btn_box.append(logout_btn)

        self._unlock_btn = Gtk.Button(label=_("Unlock"))
        self._unlock_btn.add_css_class("suggested-action")
        self._unlock_btn.add_css_class("pill")
        self._unlock_btn.set_hexpand(True)
        self._unlock_btn.connect("clicked", self._on_unlock_clicked)
        self._unlock_entry.connect("entry-activated", self._on_unlock_clicked)
        btn_box.append(self._unlock_btn)

        box.append(btn_box)
        return box

    def _build_settings_subpage(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        self._server_info_row = Adw.ActionRow(title=_("Server"), subtitle=_("Loading…"))
        list_box.append(self._server_info_row)

        self._account_row = Adw.ActionRow(title=_("Status"), subtitle=_("Unlocked ✓"))
        
        btn_box_auth = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        btn_box_auth.set_valign(Gtk.Align.CENTER)

        lock_btn = Gtk.Button(label=_("Lock"))
        lock_btn.add_css_class("flat")
        lock_btn.connect("clicked", self._on_lock_clicked)
        btn_box_auth.append(lock_btn)

        logout_btn = Gtk.Button(label=_("Log Out"))
        logout_btn.add_css_class("flat")
        logout_btn.add_css_class("destructive-action")
        logout_btn.connect("clicked", self._on_logout_clicked)
        btn_box_auth.append(logout_btn)

        self._account_row.add_suffix(btn_box_auth)
        list_box.append(self._account_row)

        self._forget_pwd_row = Adw.ActionRow(
            title=_("Saved Password"),
            subtitle=_("Master password is saved in system keyring for auto-unlock")
        )
        forget_btn = Gtk.Button(label=_("Forget"))
        forget_btn.set_valign(Gtk.Align.CENTER)
        forget_btn.add_css_class("flat")
        forget_btn.add_css_class("destructive-action")
        forget_btn.connect("clicked", self._on_forget_password_clicked)
        self._forget_pwd_row.add_suffix(forget_btn)
        list_box.append(self._forget_pwd_row)

        self._folder_items = Gtk.StringList.new()
        self._folder_combo = Adw.ComboRow(title=_("Folder"), model=self._folder_items)
        self._folder_combo_map: list[str | None] = []
        self._folder_combo.connect("notify::selected", self._on_folder_changed)
        list_box.append(self._folder_combo)

        sync_row = Adw.ActionRow(title=_("Sync Vault"), subtitle=_("Pull the latest items from the server"))
        sync_btn = Gtk.Button(label=_("Sync Now"))
        sync_btn.set_valign(Gtk.Align.CENTER)
        sync_btn.add_css_class("flat")
        sync_btn.connect("clicked", self._on_sync_clicked)
        sync_row.add_suffix(sync_btn)
        list_box.append(sync_row)

        box.append(list_box)
        return box

    def _show_toast(self, msg: str) -> None:
        toast = Adw.Toast(title=msg)
        toast.set_timeout(4)
        self._toast_overlay.add_toast(toast)

    def _run_coroutine(self, coro) -> None:
        from services.ssh_service import SSHService
        SSHService().engine.run_coroutine(coro)

    def _check_status(self) -> None:
        # Check Local Vault status first
        vm = VaultManager.get()
        local_initialized = vm.is_initialized
        local_unlocked = vm.is_unlocked

        if not local_unlocked:
            success = vm.startup()
            local_initialized = vm.is_initialized
            local_unlocked = vm.is_unlocked

        # Check Bitwarden CLI status
        if not self._vault:
            def _update_no_bw():
                if local_unlocked:
                    self._local_status_row.set_subtitle(_("Active and Auto-unlocked ✓"))
                else:
                    self._local_status_row.set_subtitle(_("Locked / Failed to initialize ⚠"))
                
                # If there's no Bitwarden CLI, show unavailability message
                self._server_info_row.set_subtitle(_("Bitwarden CLI not found"))
                self._account_row.set_subtitle(_("Unavailable"))
                self._bw_stack.set_visible_child_name("settings")
                self._main_stack.set_visible_child_name("content")
                return False
            GLib.idle_add(_update_no_bw)
            return

        # Bitwarden CLI exists
        async def _do_check():
            await self._vault.is_unlocked()
            
            state = "unauthenticated"
            server = ""
            email = ""
            try:
                import json
                status_raw = await self._vault._run_bw(["status"])
                status = json.loads(status_raw)
                state = status.get("status", "unauthenticated")
                server = status.get("serverUrl", "")
            except Exception:
                pass

            if state == "unlocked":
                try:
                    email_val, _unused = VaultManager.get().get_bitwarden_session()
                    email = email_val or ""
                except Exception:
                    pass

            def _update():
                # Update Local Vault UI status
                if local_unlocked:
                    self._local_status_row.set_subtitle(_("Active and Auto-unlocked ✓"))
                else:
                    self._local_status_row.set_subtitle(_("Locked / Failed to initialize ⚠"))

                # Update Bitwarden integration UI
                has_saved = VaultManager.get().get_bitwarden_password() is not None
                self._forget_pwd_row.set_visible(has_saved)

                if state == "unauthenticated":
                    self._server_entry.set_text(server or "")
                    self._bw_stack.set_visible_child_name("login")
                elif state == "locked":
                    saved_email = ""
                    try:
                        saved_email_val, _unused = VaultManager.get().get_bitwarden_session()
                        saved_email = saved_email_val or ""
                    except Exception:
                        pass
                    self._unlock_email_row.set_subtitle(saved_email or email or _("Logged In"))
                    self._bw_stack.set_visible_child_name("unlock")
                elif state == "unlocked":
                    self._server_info_row.set_subtitle(server or _("Official Cloud Server"))
                    self._account_row.set_subtitle(email or _("Unlocked ✓"))
                    self._bw_stack.set_visible_child_name("settings")
                    self._load_folders()

                self._main_stack.set_visible_child_name("content")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_do_check())

    def _load_folders(self) -> None:
        logger.debug("VaultManagerWindow: _load_folders() triggered.")
        async def _fetch():
            folders = []
            try:
                if hasattr(self._vault, "list_folders"):
                    logger.debug("_fetch: Calling backend list_folders()...")
                    folders = await self._vault.list_folders()
                logger.debug(f"_fetch: Returned {len(folders)} folders.")
            except Exception as e:
                logger.debug(f"_fetch: ERROR: {e}")
                GLib.idle_add(lambda: self._show_toast(_("Failed to load folders: {e}").format(e=e)) and False)
                return

            def _update():
                if not folders:
                    logger.debug("_update: Results empty, skipping UI update to avoid wipe.")
                    if self._folder_items.get_n_items() > 1:
                         return False

                logger.debug("_update: UI reconstruction starting...")
                self._ignore_folder_changes = True
                try:
                    self._folder_items.splice(0, self._folder_items.get_n_items(), [_("[All Items]")])
                    self._folder_combo_map = [None]

                    for f in folders:
                        self._folder_combo_map.append(f["id"])
                        self._folder_items.append(f["name"])

                    db = Database()
                    db.open()
                    try:
                        saved_id = db.get_meta("vault_folder_id")
                        logger.debug(f"_update: Saved folder ID from DB is: '{saved_id}'")
                    finally:
                        db.close()

                    if saved_id in self._folder_combo_map:
                        idx = self._folder_combo_map.index(saved_id)
                        logger.debug(f"_update: Found matching folder at index {idx}. Setting selected.")
                        self._folder_combo.set_selected(idx)
                    else:
                        logger.debug("_update: Saved ID not in current list or None. Defaulting to 0.")
                        self._folder_combo.set_selected(0)
                finally:
                    self._ignore_folder_changes = False
                    logger.debug("_update: UI reconstruction finished. Lock released.")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_fetch())

    def _on_folder_changed(self, *_args) -> None:
        if getattr(self, "_ignore_folder_changes", False):
            logger.debug("_on_folder_changed: Ignored (lock active).")
            return
            
        idx = self._folder_combo.get_selected()
        if 0 <= idx < len(self._folder_combo_map):
            folder_id = self._folder_combo_map[idx]
            logger.debug(f"_on_folder_changed: User selected index {idx}, ID: '{folder_id}'")
            db = Database()
            db.open()
            try:
                logger.debug(f"_on_folder_changed: Persistence - Saving '{folder_id}' to DB meta.")
                db.set_meta("vault_folder_id", folder_id or "")
            finally:
                db.close()

    _2FA_KEYWORD_MAP = [
        (["authenticator", "totp", "time-based"], _("Authenticator App (TOTP)"), 0),
        (["email"],                               _("Email Verification"),       1),
        (["yubikey", "yubi"],                     _("YubiKey OTP"),              2),
        (["duo"],                                 _("Duo"),                      3),
        (["fido", "webauthn", "hardware"],        _("FIDO2 / WebAuthn"),         4),
    ]

    def _detect_2fa_method(self, error_msg: str) -> int:
        lower = error_msg.lower()
        for keywords, _label, idx in self._2FA_KEYWORD_MAP:
            if any(kw in lower for kw in keywords):
                return idx
        return 0

    def _switch_to_2fa(self, error_msg: str = "") -> None:
        detected_idx = self._detect_2fa_method(error_msg)
        self._2fa_method_row.set_selected(detected_idx)
        self._update_2fa_hints(detected_idx)
        self._2fa_code_entry.set_text("")
        self._bw_stack.set_visible_child_name("two_factor")
        self._2fa_code_entry.grab_focus()

    def _on_2fa_method_changed(self, _row, _pspec) -> None:
        self._update_2fa_hints(self._2fa_method_row.get_selected())

    def _update_2fa_hints(self, idx: int) -> None:
        hints = [
            _("Open your authenticator app (e.g. Google Authenticator, Aegis, Ente Auth) and enter the 6-digit code."),
            _("Check your email inbox for a verification code sent by Bitwarden."),
            _("Insert your YubiKey and tap it to generate an OTP."),
            _("Approve the Duo push notification on your device, or enter the Duo passcode."),
            _("Touch your hardware security key when it lights up."),
        ]
        placeholders = [
            _("6-digit TOTP code"),
            _("Email verification code"),
            _("YubiKey OTP"),
            _("Duo passcode (or leave blank for push)"),
            _("(Not supported in CLI mode — use another method)"),
        ]
        hint = hints[idx] if idx < len(hints) else ""
        placeholder = placeholders[idx] if idx < len(placeholders) else ""
        self._2fa_hint_label.set_label(hint)
        self._2fa_code_entry.set_text("")
        self._2fa_code_entry.set_tooltip_text(placeholder)

        fido_mode = (idx == 4)
        self._2fa_submit_btn.set_sensitive(not fido_mode)
        if fido_mode:
            self._2fa_hint_label.set_label(
                _("FIDO2 / WebAuthn is not supported by the Bitwarden CLI. ") +
                _("Please use a different 2FA method (e.g. TOTP or Email).")
            )

    def _on_login_clicked(self, _btn) -> None:
        email = self._email_entry.get_text().strip()
        pwd = self._password_row.get_text()
        server = self._server_entry.get_text().strip()

        if not email or not pwd:
            self._show_toast(_("Please provide email and master password."))
            return
            
        self._login_email = email
        if self._login_pwd:
            self._login_pwd.clear()
        self._login_pwd = SecureBytes(pwd)
        self._password_row.set_text("")

        self._login_btn.set_sensitive(False)
        self._main_stack.set_visible_child_name("loading")

        async def _do_login():
            try:
                if server and "bitwarden.com" not in server:
                    try:
                        await self._vault._run_bw(["config", "server", server])
                    except Exception:
                        pass
                else:
                    try:
                        await self._vault._run_bw(["config", "server", "null"])
                    except Exception:
                        pass

                remember = self._login_remember_check.get_active()
                success = await self._vault.login(self._login_email, self._login_pwd, remember=remember)

                if success:
                    if self._login_pwd:
                        self._login_pwd.clear()
                        self._login_pwd = None
                    GLib.idle_add(
                        lambda: (self._login_btn.set_sensitive(True), self._check_status()) and False
                    )
                else:
                    GLib.idle_add(lambda: (
                        self._login_btn.set_sensitive(True),
                        self._check_status(),
                    ) and False)

            except Exception as e:
                msg = str(e)

                def _fail(err=msg):
                    self._login_btn.set_sensitive(True)
                    if self._is_2fa_required(err):
                        self._switch_to_2fa(err)
                    else:
                        self._bw_stack.set_visible_child_name("login")
                        self._main_stack.set_visible_child_name("content")
                        self._show_toast(_("Login failed: {err}").format(err=err))
                    return False

                GLib.idle_add(_fail)

        self._run_coroutine(_do_login())

    @staticmethod
    def _is_2fa_required(msg: str) -> bool:
        lower = msg.lower()
        return any(kw in lower for kw in [
            "two-step", "two step", "2fa", "two factor",
            "login code", "otp", "authenticator",
            "verification code", "method",
            "code is required", "method is required",
        ])

    def _on_2fa_submit(self, _btn) -> None:
        code = self._2fa_code_entry.get_text().strip()
        method_idx = self._2fa_method_row.get_selected()
        method_id = self._2fa_method_ids[method_idx]

        if not code and method_id != 2:
            self._show_toast(_("Please enter your verification code."))
            return

        self._2fa_submit_btn.set_sensitive(False)
        self._main_stack.set_visible_child_name("loading")

        async def _do_2fa():
            try:
                code_sb = SecureBytes(code)
                if not self._login_pwd:
                     raise RuntimeError(_("Login password missing for 2FA"))
                
                remember = self._login_remember_check.get_active()
                success = await self._vault.login(self._login_email, self._login_pwd, method=method_id, code=code_sb, remember=remember)
                code_sb.clear()
                
                if success:
                    if self._login_pwd:
                        self._login_pwd.clear()
                        self._login_pwd = None
                    GLib.idle_add(lambda: (
                        self._2fa_submit_btn.set_sensitive(True),
                        self._check_status(),
                    ) and False)
                else:
                    GLib.idle_add(lambda: (
                        self._2fa_submit_btn.set_sensitive(True),
                        self._check_status(),
                    ) and False)
            except Exception as e:
                def _fail(err=str(e)):
                    self._2fa_submit_btn.set_sensitive(True)
                    self._bw_stack.set_visible_child_name("two_factor")
                    self._main_stack.set_visible_child_name("content")
                    self._show_toast(_("Verification failed: {err}").format(err=err))
                    return False
                GLib.idle_add(_fail)

        self._run_coroutine(_do_2fa())

    def _on_unlock_clicked(self, _btn) -> None:
        pwd = self._unlock_entry.get_text()
        if not pwd:
            return

        self._unlock_btn.set_sensitive(False)
        self._main_stack.set_visible_child_name("loading")

        async def _do_unlock():
            pwd_sb = SecureBytes(self._unlock_entry.get_text())
            self._unlock_entry.set_text("")
            remember = self._unlock_remember_check.get_active()
            success = await self._vault.unlock(pwd_sb, remember=remember)
            pwd_sb.clear()

            def _update():
                self._unlock_btn.set_sensitive(True)
                if success:
                    self._check_status()
                else:
                    self._show_toast(_("Incorrect master password, or unlock failed."))
                    self._bw_stack.set_visible_child_name("unlock")
                    self._main_stack.set_visible_child_name("content")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_do_unlock())

    def _on_local_vault_reset_clicked(self, _btn) -> None:
        """Confirm and destroy the local vault DB to allow fresh start."""
        dialog = Adw.MessageDialog(
            transient_for=self.get_root(),
            heading=_("Reset Local Vault?"),
            body=_(
                "This will permanently erase all connection cache and local keys. "
                "The actual data inside Bitwarden is NOT affected. "
                "Use this to wipe all local cached credentials."
            ),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("reset", _("Reset"))
        dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def _on_response(_d, response):
            if response == "reset":
                self._main_stack.set_visible_child_name("loading")
                try:
                    # Wipe and restart the vault automatically
                    VaultManager.get().destroy_vault()
                    VaultManager.get().startup()
                    self._show_toast(_("Local vault reset successfully."))
                    self._check_status()
                    
                    # Proactively reload references in main window
                    root = self.get_root()
                    if root and hasattr(root, "_load_connections"):
                        root._load_connections()
                    if root and hasattr(root, "_hosts_page") and hasattr(root._hosts_page, "refresh"):
                        root._hosts_page.refresh()
                except Exception as e:
                    self._show_toast(_("Failed to reset vault: {e}").format(e=e))
                    self._check_status()

        dialog.connect("response", _on_response)
        dialog.present()

    def _on_lock_clicked(self, _btn) -> None:
        self._main_stack.set_visible_child_name("loading")

        async def _do_lock():
            await self._vault.lock()
            GLib.idle_add(lambda: self._check_status() or False)

        self._run_coroutine(_do_lock())

    def _on_logout_clicked(self, _btn) -> None:
        self._main_stack.set_visible_child_name("loading")

        async def _do_logout():
            await self._vault.lock()
            try:
                await self._vault._run_bw(["logout"])
            except Exception:
                pass
            GLib.idle_add(lambda: self._check_status() or False)

        self._run_coroutine(_do_logout())

    def _on_forget_password_clicked(self, _btn) -> None:
        VaultManager.get().clear_bitwarden_password()
        self._forget_pwd_row.set_visible(False)
        self._show_toast(_("Saved master password removed from keyring."))

    def _on_sync_clicked(self, _btn) -> None:
        self._show_toast(_("Syncing vault…"))

        async def _do_sync():
            try:
                await self._vault._run_bw(["sync"])
                GLib.idle_add(lambda: self._show_toast(_("Sync completed.")) or False)
                self._load_folders()
            except Exception as e:
                GLib.idle_add(lambda: self._show_toast(_("Sync failed: {e}").format(e=e)) or False)

        self._run_coroutine(_do_sync())


# Backwards-compatible alias so existing imports don't break
VaultSettingsDialog = VaultManagerWindow
