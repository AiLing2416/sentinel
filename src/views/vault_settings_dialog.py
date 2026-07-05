# SPDX-License-Identifier: GPL-3.0-or-later

"""Vault Manager Window — standalone preferences view for Bitwarden integration and Configuration Sync."""

from __future__ import annotations

import asyncio
from typing import Callable, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
import json
from gi.repository import Adw, Gtk, GLib, Pango

_ = gettext.gettext

from services.vault_service import VaultService
from services.vault_manager import VaultManager
from services.sync_manager import SyncManager
from utils.secure import SecureBytes
from db.database import Database
import logging

logger = logging.getLogger(__name__)


class SyncSettingsDialog(Adw.MessageDialog):
    """Dialog for binding Bitwarden sync note items."""

    def __init__(self, parent: Gtk.Window, vault: Any) -> None:
        super().__init__(
            transient_for=parent,
            heading=_("Configuration Sync Settings"),
            body=_("Select or create a Bitwarden Secure Note to store your Sentinel sync profile."),
        )
        self._vault = vault
        self._selected_id: str | None = None
        self._selected_name: str = "Sentinel Sync Profile"
        self._mode: str = "auto"  # "auto", "manual", "create"
        self._notes_list: list[dict] = []

        self.add_response("cancel", _("Cancel"))
        self.add_response("save", _("Save"))
        self.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        self.set_default_response("save")
        self.set_close_response("cancel")

        self._build_ui()
        self._load_data()

    def _build_ui(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        
        list_box = Gtk.ListBox()
        list_box.add_css_class("boxed-list")
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        box.append(list_box)

        # 1. Auto-detect option
        self._auto_btn = Gtk.CheckButton(active=True)
        self._auto_row = Adw.ActionRow(
            title=_("Auto-detect Sync Note"),
            subtitle=_("Search for notes with 'sentinel_sync = true' or named 'Sentinel Sync Profile'")
        )
        self._auto_row.add_prefix(self._auto_btn)
        list_box.append(self._auto_row)

        # 2. Manual select option
        self._manual_btn = Gtk.CheckButton(group=self._auto_btn)
        self._manual_row = Adw.ActionRow(
            title=_("Select Existing Note"),
            subtitle=_("Choose from your existing Bitwarden Secure Notes")
        )
        self._manual_row.add_prefix(self._manual_btn)
        list_box.append(self._manual_row)

        # ComboRow for manual select
        self._combo_items = Gtk.StringList.new()
        self._combo_row = Adw.ComboRow(
            title=_("Available Notes"),
            model=self._combo_items,
            sensitive=False
        )
        self._combo_row_map: list[dict] = []
        list_box.append(self._combo_row)

        # 3. Create new option
        self._create_btn = Gtk.CheckButton(group=self._auto_btn)
        self._create_row = Adw.ActionRow(
            title=_("Create New Sync Note"),
            subtitle=_("Create a brand-new Note in your Bitwarden vault")
        )
        self._create_row.add_prefix(self._create_btn)
        list_box.append(self._create_row)

        # EntryRow for custom name
        self._name_entry = Adw.EntryRow(
            title=_("Note Name"),
            text="Sentinel Sync Profile",
            sensitive=False
        )
        list_box.append(self._name_entry)

        # Connect events
        self._auto_btn.connect("toggled", self._on_mode_changed)
        self._manual_btn.connect("toggled", self._on_mode_changed)
        self._create_btn.connect("toggled", self._on_mode_changed)

        self.set_extra_child(box)

    def _on_mode_changed(self, _btn) -> None:
        is_auto = self._auto_btn.get_active()
        is_manual = self._manual_btn.get_active()
        is_create = self._create_btn.get_active()

        self._combo_row.set_sensitive(is_manual)
        self._name_entry.set_sensitive(is_create)

        if is_auto:
            self._mode = "auto"
        elif is_manual:
            self._mode = "manual"
        elif is_create:
            self._mode = "create"

    def _load_data(self) -> None:
        async def _fetch():
            try:
                # list_sync_notes is added to Bitwarden backend
                notes = await self._vault.list_sync_notes()
                
                def _update_ui():
                    self._notes_list = notes
                    self._combo_items.splice(0, self._combo_items.get_n_items(), [])
                    self._combo_row_map = []
                    
                    for note in notes:
                        self._combo_items.append(note["name"])
                        self._combo_row_map.append(note)
                        
                    db = Database()
                    db.open()
                    saved_id = db.get_meta("sync_item_id")
                    saved_detection = db.get_meta("sync_fields_detection", "true")
                    db.close()

                    if saved_detection == "false" and saved_id:
                        for idx, note in enumerate(self._combo_row_map):
                            if note["id"] == saved_id:
                                self._manual_btn.set_active(True)
                                self._combo_row.set_selected(idx)
                                break
                    else:
                        self._auto_btn.set_active(True)
                        
                GLib.idle_add(_update_ui)
            except Exception as e:
                logger.error(f"Failed to fetch secure notes for settings: {e}")
                
        from services.ssh_service import SSHService
        SSHService().engine.run_coroutine(_fetch())

    def get_settings(self) -> tuple[str, str, str | None, str]:
        """Returns (mode, name_to_create, selected_id, selected_name)."""
        mode = self._mode
        name = self._name_entry.get_text().strip() or "Sentinel Sync Profile"
        
        selected_id = None
        selected_name = ""
        
        if mode == "manual":
            idx = self._combo_row.get_selected()
            if 0 <= idx < len(self._combo_row_map):
                selected_id = self._combo_row_map[idx]["id"]
                selected_name = self._combo_row_map[idx]["name"]
                
        return mode, name, selected_id, selected_name


class VaultManagerWindow(Gtk.Box):
    """A settings view for managing Bitwarden settings and Configuration Sync."""

    def __init__(self, app: Adw.Application, on_close_callback: Callable[[], None] | None = None) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._app = app
        self._on_close_callback = on_close_callback
        self._vault = VaultService.get().get_backend("bitwarden")
        self._ignore_folder_changes = False
        self._login_pwd: SecureBytes | None = None
        self._login_email: str | None = None
        self._loading_sync_pref = False

        self._build_ui()
        self._check_status()

    def _build_ui(self) -> None:
        self._toast_overlay = Adw.ToastOverlay()
        self.append(self._toast_overlay)

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

        self._main_stack.add_named(content_scroll, "content")

        # Title Label
        title_label = Gtk.Label(label=_("Vault Settings"))
        title_label.add_css_class("title-1")
        title_label.set_halign(Gtk.Align.START)
        title_label.set_margin_bottom(12)
        content_box.append(title_label)

        # ── 1. Bitwarden Preferences Group ── (Moved to the top)
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

        # ── 2. Configuration Sync Preferences Group ── (Added at the bottom)
        self._sync_group = Adw.PreferencesGroup(
            title=_("Configuration Sync"),
            description=_("Sync connections, groups, and forwarding rules across devices via a Bitwarden Secure Note.")
        )

        # Enable Switch Row
        self._sync_enable_row = Adw.SwitchRow(
            title=_("Enable Configuration Sync"),
            subtitle=_("Activate Secure Note sync for this vault")
        )
        self._sync_enable_row.connect("notify::active", self._on_sync_enabled_toggled)
        self._sync_group.add(self._sync_enable_row)

        # Sync Note Selector Row
        self._sync_note_row = Adw.ActionRow(
            title=_("Sync Note Item"),
            subtitle=_("Not bound"),
            activatable=True
        )
        self._sync_note_row.connect("activated", self._on_sync_note_row_activated)
        selector_arrow = Gtk.Image.new_from_icon_name("document-edit-symbolic")
        selector_arrow.add_css_class("dim-label")
        self._sync_note_row.add_suffix(selector_arrow)
        self._sync_group.add(self._sync_note_row)

        # Auto Sync Switch Row
        self._sync_auto_row = Adw.SwitchRow(
            title=_("Auto Sync on Changes"),
            subtitle=_("Automatically upload changes to Bitwarden note in background")
        )
        self._sync_auto_row.connect("notify::active", self._on_sync_auto_toggled)
        self._sync_group.add(self._sync_auto_row)

        # Sync Action Buttons Row
        self._sync_actions_row = Adw.ActionRow(
            title=_("Sync Actions"),
            subtitle=_("Manually push local configuration or pull from Bitwarden note")
        )
        
        sync_actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        sync_actions_box.set_valign(Gtk.Align.CENTER)

        self._push_btn = Gtk.Button(label=_("Upload (Push)"))
        self._push_btn.add_css_class("flat")
        self._push_btn.connect("clicked", self._on_push_clicked)
        sync_actions_box.append(self._push_btn)

        self._pull_btn = Gtk.Button(label=_("Download (Pull)"))
        self._pull_btn.add_css_class("flat")
        self._pull_btn.connect("clicked", self._on_pull_clicked)
        sync_actions_box.append(self._pull_btn)

        self._sync_actions_row.add_suffix(sync_actions_box)
        self._sync_group.add(self._sync_actions_row)

        # Sync Note Usage Row
        self._sync_usage_row = Adw.ActionRow(
            title=_("Sync Note Usage"),
            subtitle=_("0 / 10000 characters used")
        )
        self._usage_progress = Gtk.ProgressBar()
        self._usage_progress.set_valign(Gtk.Align.CENTER)
        self._usage_progress.set_size_request(150, -1)
        self._sync_usage_row.add_suffix(self._usage_progress)
        self._sync_group.add(self._sync_usage_row)

        content_box.append(self._sync_group)

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
        # Check Local Vault status first in backend (keeps initialized and auto-unlocked)
        vm = VaultManager.get()
        local_unlocked = vm.is_unlocked
        if not local_unlocked:
            vm.startup()
            local_unlocked = vm.is_unlocked

        # Check Bitwarden CLI status
        if not self._vault:
            def _update_no_bw():
                self._server_info_row.set_subtitle(_("Bitwarden CLI not found"))
                self._account_row.set_subtitle(_("Unavailable"))
                self._bw_stack.set_visible_child_name("settings")
                self._sync_group.set_sensitive(False)
                self._main_stack.set_visible_child_name("content")
                return False
            GLib.idle_add(_update_no_bw)
            return

        async def _do_check():
            await self._vault.is_unlocked()
            
            state = "unauthenticated"
            server = ""
            email = ""
            try:
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

                # Update Sync preferences card group
                self._update_sync_ui(state)

                self._main_stack.set_visible_child_name("content")
                return False

            GLib.idle_add(_update)

        self._run_coroutine(_do_check())

    def _update_sync_ui(self, bw_state: str) -> None:
        db = Database()
        db.open()
        try:
            sync_enabled = db.get_meta("sync_enabled", "false") == "true"
            sync_auto = db.get_meta("sync_auto", "false") == "true"
            sync_item_name = db.get_meta("sync_item_name", "")
            sync_detection = db.get_meta("sync_fields_detection", "true") == "true"
        finally:
            db.close()

        is_unlocked_bw = (bw_state == "unlocked")
        self._sync_group.set_sensitive(is_unlocked_bw)

        # Temporarily block callbacks using a flag
        self._loading_sync_pref = True
        try:
            self._sync_enable_row.set_active(sync_enabled)
            self._sync_auto_row.set_active(sync_auto)
        finally:
            self._loading_sync_pref = False

        self._sync_note_row.set_sensitive(sync_enabled)
        self._sync_auto_row.set_sensitive(sync_enabled)
        self._sync_actions_row.set_sensitive(sync_enabled)

        if sync_item_name:
            if sync_detection:
                self._sync_note_row.set_subtitle(f"{sync_item_name} ({_('Auto-detect')})")
            else:
                self._sync_note_row.set_subtitle(f"{sync_item_name} ({_('Manual')})")
        else:
            self._sync_note_row.set_subtitle(_("Not bound"))

        # Update sync usage progress row
        if is_unlocked_bw and sync_enabled:
            self._sync_usage_row.set_visible(True)
            try:
                config = SyncManager.get().serialize_local_config()
                payload = SyncManager.get().encrypt_data(config)
                size = len(payload)
            except Exception as e:
                logger.error(f"Failed to calculate sync note usage: {e}")
                size = 0
            
            percentage = min(1.0, size / 10000.0)
            self._usage_progress.set_fraction(percentage)
            self._sync_usage_row.set_subtitle(
                _("{size} / 10000 characters used ({percent:.1%})").format(size=size, percent=percentage)
            )
            
            # Apply styling if it gets close to limit
            self._usage_progress.remove_css_class("error")
            self._usage_progress.remove_css_class("warning")
            if size >= 10000:
                self._usage_progress.add_css_class("error")
            elif size >= 8000:
                self._usage_progress.add_css_class("warning")
        else:
            self._sync_usage_row.set_visible(False)

    def _on_sync_enabled_toggled(self, row: Adw.SwitchRow, _pspec) -> None:
        if getattr(self, "_loading_sync_pref", False):
            return
        active = row.get_active()
        db = Database()
        db.open()
        try:
            db.set_meta("sync_enabled", "true" if active else "false")
            item_id = db.get_meta("sync_item_id")
        finally:
            db.close()

        self._sync_note_row.set_sensitive(active)
        self._sync_auto_row.set_sensitive(active)
        self._sync_actions_row.set_sensitive(active)

        if active and not item_id:
            self._auto_detect_sync_note()
        else:
            self._update_sync_ui("unlocked")

    def _on_sync_auto_toggled(self, row: Adw.SwitchRow, _pspec) -> None:
        if getattr(self, "_loading_sync_pref", False):
            return
        active = row.get_active()
        db = Database()
        db.open()
        try:
            db.set_meta("sync_auto", "true" if active else "false")
        finally:
            db.close()

    def _on_sync_note_row_activated(self, _row: Adw.ActionRow) -> None:
        dialog = SyncSettingsDialog(self.get_root(), self._vault)
        
        def _on_response(d: SyncSettingsDialog, response: str):
            if response == "save":
                mode, name, selected_id, selected_name = d.get_settings()
                self._main_stack.set_visible_child_name("loading")
                
                async def _apply_settings():
                    try:
                        if mode == "auto":
                            notes = await self._vault.list_sync_notes()
                            match = await self._find_best_sync_note(notes)
                            if match:
                                def _save_auto(found=match):
                                    db = Database()
                                    db.open()
                                    try:
                                        db.set_meta("sync_item_id", found["id"])
                                        db.set_meta("sync_item_name", found["name"])
                                        db.set_meta("sync_fields_detection", "true")
                                    finally:
                                        db.close()
                                    self._show_toast(_("Bound to auto-detected note: {name}").format(name=found["name"]))
                                    self._check_status()
                                GLib.idle_add(_save_auto)
                            else:
                                # Create default Sentinel Sync Profile in Bitwarden
                                config_data = SyncManager.get().serialize_local_config()
                                payload = SyncManager.get().encrypt_data(config_data)
                                new_id = await self._vault.create_sync_note("Sentinel Sync Profile", payload)
                                
                                def _save_new(nid=new_id):
                                    db = Database()
                                    db.open()
                                    try:
                                        db.set_meta("sync_item_id", nid)
                                        db.set_meta("sync_item_name", "Sentinel Sync Profile")
                                        db.set_meta("sync_fields_detection", "true")
                                    finally:
                                        db.close()
                                    self._show_toast(_("Created new sync note: Sentinel Sync Profile"))
                                    self._check_status()
                                GLib.idle_add(_save_new)
                                
                        elif mode == "create":
                            config_data = SyncManager.get().serialize_local_config()
                            payload = SyncManager.get().encrypt_data(config_data)
                            new_id = await self._vault.create_sync_note(name, payload)
                            
                            def _save_created(nid=new_id, nname=name):
                                db = Database()
                                db.open()
                                try:
                                    db.set_meta("sync_item_id", nid)
                                    db.set_meta("sync_item_name", nname)
                                    db.set_meta("sync_fields_detection", "false")
                                finally:
                                    db.close()
                                self._show_toast(_("Created new sync note: {name}").format(name=nname))
                                self._check_status()
                            GLib.idle_add(_save_created)
                            
                        elif mode == "manual":
                            if not selected_id:
                                raise ValueError(_("No note selected"))
                            
                            def _save_manual(nid=selected_id, nname=selected_name):
                                db = Database()
                                db.open()
                                try:
                                    db.set_meta("sync_item_id", nid)
                                    db.set_meta("sync_item_name", nname)
                                    db.set_meta("sync_fields_detection", "false")
                                finally:
                                    db.close()
                                self._show_toast(_("Bound to note: {name}").format(name=nname))
                                self._check_status()
                            GLib.idle_add(_save_manual)
                            
                    except Exception as e:
                        err_msg = str(e)
                        GLib.idle_add(lambda err=err_msg: (
                            self._show_toast(_("Failed to configure sync note: {e}").format(e=err)),
                            self._check_status()
                        ) and False)
                
                self._run_coroutine(_apply_settings())
            else:
                self._check_status()
                
        dialog.connect("response", _on_response)
        dialog.present()

    async def _find_best_sync_note(self, notes: list[dict]) -> dict | None:
        """Find the best matching sync note using a robust multi-stage detection algorithm."""
        match = None
        # Stage 1: Marked with sentinel_sync AND can be successfully decrypted
        for n in notes:
            if n.get("is_sentinel_sync"):
                try:
                    content = await self._vault.get_sync_note(n["id"])
                    decrypted = SyncManager.get().decrypt_data(content)
                    if "connections" in decrypted:
                        match = n
                        break
                except Exception:
                    pass

        # Stage 2: Marked with sentinel_sync only
        if not match:
            for n in notes:
                if n.get("is_sentinel_sync"):
                    match = n
                    break

        # Stage 3: Named 'Sentinel Sync Profile' AND can be successfully decrypted
        if not match:
            for n in notes:
                if n.get("name") == "Sentinel Sync Profile":
                    try:
                        content = await self._vault.get_sync_note(n["id"])
                        decrypted = SyncManager.get().decrypt_data(content)
                        if "connections" in decrypted:
                            match = n
                            break
                    except Exception:
                        pass

        # Stage 4: Named 'Sentinel Sync Profile' only
        if not match:
            for n in notes:
                if n.get("name") == "Sentinel Sync Profile":
                    match = n
                    break

        return match

    def _auto_detect_sync_note(self) -> None:
        async def _do_detect():
            try:
                notes = await self._vault.list_sync_notes()
                match = await self._find_best_sync_note(notes)
                            
                def _update(found=match):
                    if found:
                        db = Database()
                        db.open()
                        try:
                            db.set_meta("sync_item_id", found["id"])
                            db.set_meta("sync_item_name", found["name"])
                            db.set_meta("sync_fields_detection", "true")
                        finally:
                            db.close()
                        self._show_toast(_("Auto-detected sync note: {name}").format(name=found["name"]))
                    else:
                        self._show_toast(_("No existing sync note found. Please select or create one."))
                    self._check_status()
                    
                GLib.idle_add(_update)
            except Exception as e:
                logger.error(f"Auto detection failed: {e}")
                
        self._run_coroutine(_do_detect())

    def _on_push_clicked(self, _btn) -> None:
        db = Database()
        db.open()
        try:
            item_id = db.get_meta("sync_item_id")
        finally:
            db.close()
        
        if not item_id:
            self._show_toast(_("Please configure a sync note first."))
            return
            
        self._push_btn.set_sensitive(False)
        self._show_toast(_("Uploading configuration to Bitwarden…"))
        
        async def _do_push():
            try:
                await SyncManager.get().push_sync(item_id)
                GLib.idle_add(lambda: (
                    self._push_btn.set_sensitive(True),
                    self._update_sync_ui("unlocked"),
                    self._show_toast(_("Configuration uploaded successfully ✓"))
                ) and False)
            except Exception as e:
                err_msg = str(e)
                GLib.idle_add(lambda err=err_msg: (
                    self._push_btn.set_sensitive(True),
                    self._show_toast(_("Upload failed: {e}").format(e=err))
                ) and False)
                
        self._run_coroutine(_do_push())

    def _on_pull_clicked(self, _btn) -> None:
        db = Database()
        db.open()
        try:
            item_id = db.get_meta("sync_item_id")
        finally:
            db.close()
        
        if not item_id:
            self._show_toast(_("Please configure a sync note first."))
            return
            
        self._pull_btn.set_sensitive(False)
        self._show_toast(_("Downloading configuration from Bitwarden…"))
        
        async def _do_pull():
            try:
                await SyncManager.get().pull_sync(item_id)
                
                def _success():
                    self._pull_btn.set_sensitive(True)
                    self._update_sync_ui("unlocked")
                    self._show_toast(_("Configuration downloaded and merged successfully ✓"))
                    root = self.get_root()
                    if root and hasattr(root, "_load_connections"):
                        root._load_connections()
                    if root and hasattr(root, "_hosts_page") and hasattr(root._hosts_page, "refresh"):
                        root._hosts_page.refresh()
                        
                GLib.idle_add(_success)
            except Exception as e:
                err_msg = str(e)
                GLib.idle_add(lambda err=err_msg: (
                    self._pull_btn.set_sensitive(True),
                    self._show_toast(_("Download failed: {e}").format(e=err))
                ) and False)
                
        self._run_coroutine(_do_pull())

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
        self._main_stack.set_visible_child_name("content")
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

                success = await self._vault.login(self._login_email, self._login_pwd, remember=False)

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
                
                success = await self._vault.login(self._login_email, self._login_pwd, method=method_id, code=code_sb, remember=False)
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
            success = await self._vault.unlock(pwd_sb, remember=False)
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

    def _on_sync_clicked(self, _btn) -> None:
        self._show_toast(_("Syncing vault…"))

        async def _do_sync():
            try:
                await self._vault._run_bw(["sync"])
                GLib.idle_add(lambda: self._show_toast(_("Sync completed.")) or False)
                self._load_folders()
            except Exception as e:
                err_msg = str(e)
                GLib.idle_add(lambda err=err_msg: self._show_toast(_("Sync failed: {e}").format(e=err)) or False)

        self._run_coroutine(_do_sync())


# Backwards-compatible alias so existing imports don't break
VaultSettingsDialog = VaultManagerWindow
