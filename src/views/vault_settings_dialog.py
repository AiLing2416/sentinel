# SPDX-License-Identifier: GPL-3.0-or-later

"""Vault Manager Window — standalone window for Bitwarden login, unlock and folder management."""

from __future__ import annotations

import asyncio
from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
from gi.repository import Adw, Gtk, GLib

_ = gettext.gettext

from services.vault_service import VaultService
from services.vault_manager import VaultManager
from utils.secure import SecureBytes
from db.database import Database
import logging

logger = logging.getLogger(__name__)


class VaultManagerWindow(Adw.Window):
    """A standalone window for managing Bitwarden Vault settings.
    
    Opens independently of the main window so the user can log in,
    unlock, and choose a default folder without blocking the main UI.
    """

    def __init__(self, app: Adw.Application, on_close_callback: Callable[[], None] | None = None) -> None:
        super().__init__(
            application=app,
            title=_("Vault Manager"),
            default_width=480,
            default_height=560,
            resizable=False,
        )
        self._app = app
        self._on_close_callback = on_close_callback
        self._vault = VaultService.get().get_backend("bitwarden")
        self._ignore_folder_changes = False
        self._login_pwd: SecureBytes | None = None

        self.connect("close-request", self._on_window_close)

        self._build_ui()
        self._check_status()

    def _on_window_close(self, _window) -> bool:
        if self._login_pwd:
            self._login_pwd.clear()
            self._login_pwd = None
        if self._on_close_callback:
            self._on_close_callback()
        return False  # Allow close

    def _build_ui(self) -> None:
        self._toast_overlay = Adw.ToastOverlay()

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(True)
        toolbar.add_top_bar(header)

        self._stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=250,
        )

        self._loading_page = self._build_loading_page()
        self._stack.add_named(self._loading_page, "loading")

        # ── Local Vault pages (new) ──
        self._vault_setup_page = self._build_vault_setup_page()
        self._stack.add_named(self._vault_setup_page, "vault_setup")

        self._vault_unlock_page = self._build_vault_unlock_page()
        self._stack.add_named(self._vault_unlock_page, "vault_unlock")

        self._login_page = self._build_login_page()
        self._stack.add_named(self._login_page, "login")

        self._two_factor_page = self._build_two_factor_page()
        self._stack.add_named(self._two_factor_page, "two_factor")

        self._unlock_page = self._build_unlock_page()
        self._stack.add_named(self._unlock_page, "unlock")

        self._settings_page = self._build_settings_page()
        self._stack.add_named(self._settings_page, "settings")

        toolbar.set_content(self._stack)
        self._toast_overlay.set_child(toolbar)
        self.set_content(self._toast_overlay)

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

    def _build_vault_setup_page(self) -> Gtk.Widget:
        """First-time setup: user creates a master password for the local vault."""
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24); box.set_margin_end(24)
        box.set_margin_top(24); box.set_margin_bottom(24)

        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        icon = Gtk.Image.new_from_icon_name("preferences-system-privacy-symbolic")
        icon.set_pixel_size(48); icon.add_css_class("accent"); icon.set_margin_bottom(8)
        header_box.append(icon)

        title = Gtk.Label(label=_("Set Up Local Vault"))
        title.add_css_class("title-2")
        header_box.append(title)

        desc = Gtk.Label(
            label=_(
                "Sentinel stores credentials in an encrypted local database. "
                "Please pick a strong master password. You will only need to enter it once — "
                "after that, it is stored securely in the system keyring."
            ),
            xalign=0.5, wrap=True, justify=Gtk.Justification.CENTER,
        )
        desc.add_css_class("dim-label")
        header_box.append(desc)
        box.append(header_box)

        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        self._setup_pwd_entry = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._setup_pwd_entry)

        self._setup_pwd_confirm = Adw.PasswordEntryRow(title=_("Confirm Password"))
        list_box.append(self._setup_pwd_confirm)
        box.append(list_box)

        self._setup_btn = Gtk.Button(label=_("Create Vault"))
        self._setup_btn.add_css_class("suggested-action")
        self._setup_btn.add_css_class("pill")
        self._setup_btn.set_hexpand(True)
        self._setup_btn.connect("clicked", self._on_vault_setup_clicked)
        self._setup_pwd_confirm.connect("entry-activated", self._on_vault_setup_clicked)
        box.append(self._setup_btn)

        scroll.set_child(box)
        return scroll

    def _build_vault_unlock_page(self) -> Gtk.Widget:
        """Page for entering the master password when auto-unlock from keyring fails."""
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24); box.set_margin_end(24)
        box.set_margin_top(24); box.set_margin_bottom(24)

        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
        icon.set_pixel_size(48); icon.add_css_class("warning"); icon.set_margin_bottom(8)
        header_box.append(icon)

        title = Gtk.Label(label=_("Unlock Local Vault"))
        title.add_css_class("title-2")
        header_box.append(title)

        desc = Gtk.Label(
            label=_("Enter your Sentinel vault master password to continue."),
            xalign=0.5, wrap=True, justify=Gtk.Justification.CENTER,
        )
        desc.add_css_class("dim-label")
        header_box.append(desc)
        box.append(header_box)

        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self._vaultunlock_entry = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._vaultunlock_entry)
        box.append(list_box)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, halign=Gtk.Align.FILL)
        btn_box.set_hexpand(True)

        self._vaultunlock_btn = Gtk.Button(label=_("Unlock"))
        self._vaultunlock_btn.add_css_class("suggested-action")
        self._vaultunlock_btn.add_css_class("pill")
        self._vaultunlock_btn.set_hexpand(True)
        self._vaultunlock_btn.connect("clicked", self._on_local_vault_unlock_clicked)
        self._vaultunlock_entry.connect("entry-activated", self._on_local_vault_unlock_clicked)
        btn_box.append(self._vaultunlock_btn)
        box.append(btn_box)

        scroll.set_child(box)
        return scroll

    # ── Local Vault Actions ───────────────────────────────────

    def _on_vault_setup_clicked(self, _btn) -> None:
        pwd = self._setup_pwd_entry.get_text()
        confirm = self._setup_pwd_confirm.get_text()
        if not pwd:
            self._show_toast(_("Please enter a master password."))
            return
        if pwd != confirm:
            self._show_toast(_("Passwords do not match."))
            return
        if len(pwd) < 8:
            self._show_toast(_("Password must be at least 8 characters."))
            return

        pwd_sb = SecureBytes(pwd)
        self._setup_pwd_entry.set_text("")
        self._setup_pwd_confirm.set_text("")
        self._setup_btn.set_sensitive(False)
        self._stack.set_visible_child_name("loading")

        try:
            VaultManager.get().initialize(pwd_sb)
            pwd_sb.clear()
            self._show_toast(_("Local vault created successfully."))
            self._check_status()
        except Exception as e:
            pwd_sb.clear()
            self._setup_btn.set_sensitive(True)
            self._stack.set_visible_child_name("vault_setup")
            self._show_toast(_("Failed to create vault: {e}").format(e=e))

    def _on_local_vault_unlock_clicked(self, _btn) -> None:
        pwd = self._vaultunlock_entry.get_text()
        if not pwd:
            return
        pwd_sb = SecureBytes(pwd)
        self._vaultunlock_entry.set_text("")
        self._vaultunlock_btn.set_sensitive(False)
        self._stack.set_visible_child_name("loading")

        ok = VaultManager.get().unlock(pwd_sb)
        pwd_sb.clear()

        if ok:
            self._check_status()
        else:
            self._vaultunlock_btn.set_sensitive(True)
            self._stack.set_visible_child_name("vault_unlock")
            self._show_toast(_("Wrong master password."))

    def _build_login_page(self) -> Gtk.Widget:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        # Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        icon.set_pixel_size(48)
        icon.add_css_class("accent")
        icon.set_margin_bottom(8)
        header_box.append(icon)

        title = Gtk.Label(label=_("Log in to Bitwarden"))
        title.add_css_class("title-2")
        header_box.append(title)
 
        desc = Gtk.Label(
            label=_("Enter your credentials to access your vault."),
            xalign=0.5,
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        desc.add_css_class("dim-label")
        header_box.append(desc)
        box.append(header_box)

        # Form
        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        # Server URL (collapsed by default, expand on click)
        self._server_entry = Gtk.Entry()
        self._server_entry.set_placeholder_text(_("https://bitwarden.com (leave blank for default)"))
        self._server_entry.set_hexpand(True)
        srv_row = Adw.ExpanderRow(title=_("Custom Server"), subtitle=_("For self-hosted Bitwarden / VaultWarden"))
        self._server_entry.set_margin_top(6)
        self._server_entry.set_margin_bottom(6)
        self._server_entry.set_margin_start(12)
        self._server_entry.set_margin_end(12)
        srv_row.add_row(self._server_entry)
        list_box.append(srv_row)

        # Email
        self._email_entry = Adw.EntryRow(title=_("Email Address"))
        list_box.append(self._email_entry)
 
        # Password
        self._password_row = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._password_row)

        self._login_remember_check = Gtk.CheckButton(label=_("Save master password securely in system keyring"))
        self._login_remember_check.set_active(True)
        self._login_remember_check.set_margin_top(8)
        self._login_remember_check.set_margin_bottom(8)
        
        box.append(list_box)
        box.append(self._login_remember_check)

        # Login button
        self._login_btn = Gtk.Button(label=_("Log In"))
        self._login_btn.add_css_class("suggested-action")
        self._login_btn.add_css_class("pill")
        self._login_btn.set_halign(Gtk.Align.FILL)
        self._login_btn.set_hexpand(True)
        self._login_btn.connect("clicked", self._on_login_clicked)
        self._password_row.connect("entry-activated", self._on_login_clicked)
        box.append(self._login_btn)

        scroll.set_child(box)
        return scroll

    def _build_two_factor_page(self) -> Gtk.Widget:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        # Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        icon = Gtk.Image.new_from_icon_name("smartphone-symbolic")
        icon.set_pixel_size(48)
        icon.add_css_class("accent")
        icon.set_margin_bottom(8)
        header_box.append(icon)

        title = Gtk.Label(label=_("Two-Step Verification"))
        title.add_css_class("title-2")
        header_box.append(title)
 
        self._2fa_desc_label = Gtk.Label(
            label=_("Your account requires two-step verification."),
            xalign=0.5,
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        self._2fa_desc_label.add_css_class("dim-label")
        header_box.append(self._2fa_desc_label)
        box.append(header_box)

        # Method + code form
        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        # Method names and their corresponding bw --method IDs
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

        # Helper label (shown for certain methods)
        self._2fa_hint_label = Gtk.Label(xalign=0, wrap=True)
        self._2fa_hint_label.add_css_class("dim-label")
        self._2fa_hint_label.add_css_class("caption")
        self._2fa_hint_label.set_margin_top(4)
        box.append(self._2fa_hint_label)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, halign=Gtk.Align.FILL)
        btn_box.set_margin_top(4)
        btn_box.set_hexpand(True)

        back_btn = Gtk.Button(label=_("Back"))
        back_btn.add_css_class("pill")
        back_btn.set_hexpand(True)
        back_btn.connect("clicked", lambda _: self._stack.set_visible_child_name("login"))
        btn_box.append(back_btn)

        self._2fa_submit_btn = Gtk.Button(label=_("Verify & Log In"))
        self._2fa_submit_btn.add_css_class("suggested-action")
        self._2fa_submit_btn.add_css_class("pill")
        self._2fa_submit_btn.set_hexpand(True)
        self._2fa_submit_btn.connect("clicked", self._on_2fa_submit)
        self._2fa_code_entry.connect("entry-activated", self._on_2fa_submit)
        btn_box.append(self._2fa_submit_btn)
        box.append(btn_box)

        scroll.set_child(box)
        return scroll

    def _build_unlock_page(self) -> Gtk.Widget:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        # Header
        header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic")
        icon.set_pixel_size(48)
        icon.add_css_class("warning")
        icon.set_margin_bottom(8)
        header_box.append(icon)

        title = Gtk.Label(label=_("Vault Locked"))
        title.add_css_class("title-2")
        header_box.append(title)
 
        desc = Gtk.Label(
            label=_("Enter your master password to unlock."),
            xalign=0.5,
            wrap=True,
            justify=Gtk.Justification.CENTER,
        )
        desc.add_css_class("dim-label")
        header_box.append(desc)
        box.append(header_box)

        # Form
        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        self._unlock_entry = Adw.PasswordEntryRow(title=_("Master Password"))
        list_box.append(self._unlock_entry)

        self._unlock_remember_check = Gtk.CheckButton(label=_("Save master password securely in system keyring"))
        self._unlock_remember_check.set_active(True)
        self._unlock_remember_check.set_margin_top(8)
        self._unlock_remember_check.set_margin_bottom(8)
        
        box.append(list_box)
        box.append(self._unlock_remember_check)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, halign=Gtk.Align.FILL)
        btn_box.set_hexpand(True)

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

        scroll.set_child(box)
        return scroll

    def _build_settings_page(self) -> Gtk.Widget:
        scroll = Gtk.ScrolledWindow(vexpand=True)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_start(24)
        box.set_margin_end(24)
        box.set_margin_top(24)
        box.set_margin_bottom(24)

        # Auth group
        auth_group = Adw.PreferencesGroup(title=_("Account"))

        self._server_info_row = Adw.ActionRow(title=_("Server"), subtitle=_("Loading…"))
        auth_group.add(self._server_info_row)
 
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
        auth_group.add(self._account_row)

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
        auth_group.add(self._forget_pwd_row)

        box.append(auth_group)

        # Folder group
        folder_group = Adw.PreferencesGroup(
            title=_("Default Folder for Key Selection"),
            description=_("Only items inside this folder will appear when picking a vault SSH key in connection settings. Leave as 'All Items' to search everywhere."),
        )

        self._folder_items = Gtk.StringList.new()
        self._folder_combo = Adw.ComboRow(title=_("Folder"), model=self._folder_items)
        self._folder_combo_map: list[str | None] = []
        self._folder_combo.connect("notify::selected", self._on_folder_changed)
        folder_group.add(self._folder_combo)

        # Sync button
        sync_row = Adw.ActionRow(title=_("Sync Vault"), subtitle=_("Pull the latest items from the server"))
        sync_btn = Gtk.Button(label=_("Sync Now"))
        sync_btn.set_valign(Gtk.Align.CENTER)
        sync_btn.add_css_class("flat")
        sync_btn.connect("clicked", self._on_sync_clicked)
        sync_row.add_suffix(sync_btn)
        folder_group.add(sync_row)

        box.append(folder_group)

        scroll.set_child(box)
        return scroll

    # ── Helpers ──────────────────────────────────────────────

    def _show_toast(self, msg: str) -> None:
        toast = Adw.Toast(title=msg)
        toast.set_timeout(4)
        self._toast_overlay.add_toast(toast)

    def _run_coroutine(self, coro) -> None:
        from services.ssh_service import SSHService
        SSHService().engine.run_coroutine(coro)

    # ── Status Check ─────────────────────────────────────────

    def _check_status(self) -> None:
        if not self._vault:
            self._stack.set_visible_child_name("login")
            self._show_toast(_("Bitwarden CLI ('bw') not found. Please install it."))
            return

        self._stack.set_visible_child_name("loading")

        # ── Ensure the local SecureVault is unlocked ──
        vm = VaultManager.get()
        if not vm.is_unlocked:
            vm.startup()  # Auto-initializes on first run; silently no-ops if keyring unavailable

        # ── Check Bitwarden CLI status ──
        async def _do_check():
            # Trigger backend's is_unlocked() which now includes auto-unlock-from-keyring logic
            await self._vault.is_unlocked()
            
            state = "unauthenticated"
            server = ""
            try:
                import json
                status_raw = await self._vault._run_bw(["status"])
                status = json.loads(status_raw)
                state = status.get("status", "unauthenticated")
                server = status.get("serverUrl", "")
            except Exception:
                pass

            def _update():
                # Update Forget button visibility
                from services.vault_manager import VaultManager
                has_saved = VaultManager.get().get_bitwarden_password() is not None
                self._forget_pwd_row.set_visible(has_saved)

                if state == "unauthenticated":
                    self._server_entry.set_text(server or "")
                    self._stack.set_visible_child_name("login")
                    self._email_entry.grab_focus()
                elif state == "locked":
                    self._stack.set_visible_child_name("unlock")
                    self._unlock_entry.grab_focus()
                elif state == "unlocked":
                    self._server_info_row.set_subtitle(server or _("Official Cloud Server"))
                    self._account_row.set_subtitle(_("Unlocked ✓"))
                    self._stack.set_visible_child_name("settings")
                    self._load_folders()
                else:
                    self._stack.set_visible_child_name("login")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_do_check())

    # ── Folder Loading ────────────────────────────────────────

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

    # ── 2FA Helpers ──────────────────────────────────────────

    # Maps keywords in bw error output → (display name, method index in _2fa_method_ids)
    _2FA_KEYWORD_MAP = [
        (["authenticator", "totp", "time-based"], _("Authenticator App (TOTP)"), 0),
        (["email"],                               _("Email Verification"),       1),
        (["yubikey", "yubi"],                     _("YubiKey OTP"),              2),
        (["duo"],                                 _("Duo"),                      3),
        (["fido", "webauthn", "hardware"],        _("FIDO2 / WebAuthn"),         4),
    ]

    def _detect_2fa_method(self, error_msg: str) -> int:
        """Return best-guess index into _2fa_method_ids from error text. Defaults to 0 (TOTP)."""
        lower = error_msg.lower()
        for keywords, _label, idx in self._2FA_KEYWORD_MAP:
            if any(kw in lower for kw in keywords):
                return idx
        return 0  # Default: TOTP

    def _switch_to_2fa(self, error_msg: str = "") -> None:
        """Navigate to the 2FA page, pre-selecting the detected method."""
        detected_idx = self._detect_2fa_method(error_msg)
        self._2fa_method_row.set_selected(detected_idx)
        self._update_2fa_hints(detected_idx)
        self._2fa_code_entry.set_text("")
        self._stack.set_visible_child_name("two_factor")
        self._2fa_code_entry.grab_focus()

    def _on_2fa_method_changed(self, _row, _pspec) -> None:
        self._update_2fa_hints(self._2fa_method_row.get_selected())

    def _update_2fa_hints(self, idx: int) -> None:
        """Update descriptive hint label and entry placeholder for the selected 2FA method."""
        hints = [
            # TOTP
            _("Open your authenticator app (e.g. Google Authenticator, Aegis, Ente Auth) and enter the 6-digit code."),
            # Email
            _("Check your email inbox for a verification code sent by Bitwarden."),
            # YubiKey
            _("Insert your YubiKey and tap it to generate an OTP."),
            # Duo
            _("Approve the Duo push notification on your device, or enter the Duo passcode."),
            # FIDO2
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

        # FIDO2 not supported via CLI — disable submit
        fido_mode = (idx == 4)
        self._2fa_submit_btn.set_sensitive(not fido_mode)
        if fido_mode:
            self._2fa_hint_label.set_label(
                _("FIDO2 / WebAuthn is not supported by the Bitwarden CLI. ") +
                _("Please use a different 2FA method (e.g. TOTP or Email).")
            )

    # ── Login Flow ───────────────────────────────────────────

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
        self._stack.set_visible_child_name("loading")

        async def _do_login():
            try:
                # Optionally configure server
                if server and "bitwarden.com" not in server:
                    try:
                        await self._vault._run_bw(["config", "server", server])
                    except Exception:
                        pass
                else:
                    # Reset to official cloud
                    try:
                        await self._vault._run_bw(["config", "server", "null"])
                    except Exception:
                        pass

                # Use backend.login which handles stdin securely
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
                        self._stack.set_visible_child_name("login")
                        self._show_toast(_("Login failed: {err}").format(err=err))
                    return False

                GLib.idle_add(_fail)

        self._run_coroutine(_do_login())

    @staticmethod
    def _is_2fa_required(msg: str) -> bool:
        """Return True if the error indicates a 2FA code is required."""
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

        # Duo push (method_id=2): code can be blank (push notification)
        # All other methods need a code
        if not code and method_id != 2:
            self._show_toast(_("Please enter your verification code."))
            return

        self._2fa_submit_btn.set_sensitive(False)
        self._stack.set_visible_child_name("loading")

        # Build command — only include --code when we actually have one
        cmd = [
            "login", self._login_email, self._login_pwd,
            "--method", str(method_id),
            "--raw", "--nointeraction",
        ]
        if code:
            cmd.extend(["--code", code])

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
                    self._stack.set_visible_child_name("two_factor")
                    self._show_toast(_("Verification failed: {err}").format(err=err))
                    return False
                GLib.idle_add(_fail)

        self._run_coroutine(_do_2fa())

    # ── Unlock / Lock / Logout ────────────────────────────────

    def _on_unlock_clicked(self, _btn) -> None:
        pwd = self._unlock_entry.get_text()
        if not pwd:
            return

        self._unlock_btn.set_sensitive(False)
        self._stack.set_visible_child_name("loading")

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
                    self._stack.set_visible_child_name("unlock")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_do_unlock())

    def _on_lock_clicked(self, _btn) -> None:
        self._stack.set_visible_child_name("loading")

        async def _do_lock():
            await self._vault.lock()
            GLib.idle_add(lambda: self._check_status() or False)

        self._run_coroutine(_do_lock())

    def _on_logout_clicked(self, _btn) -> None:
        self._stack.set_visible_child_name("loading")

        async def _do_logout():
            await self._vault.lock()
            try:
                await self._vault._run_bw(["logout"])
            except Exception:
                pass
            GLib.idle_add(lambda: self._check_status() or False)

        self._run_coroutine(_do_logout())

    def _on_forget_password_clicked(self, _btn) -> None:
        from services.vault_manager import VaultManager
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
