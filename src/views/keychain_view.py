# SPDX-License-Identifier: GPL-3.0-or-later

"""Keychain Page — ssh key manager."""

from __future__ import annotations

import logging
import uuid
from typing import Any

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango

from services.vault_manager import VaultManager
from utils.secure import SecureBytes
from utils.ssh_key_utils import (
    generate_key_pair,
    extract_public_key_from_private,
)

logger = logging.getLogger(__name__)
import gettext
_ = gettext.gettext


class KeyCard(Gtk.FlowBoxChild):
    """A card representing a single SSH key in the Keychain grid."""

    # Map key type string prefix -> CSS accent class (left color bar)
    _KEY_ACCENT: dict[str, str] = {
        "ED25519": "key-accent-ed25519",
        "RSA":     "key-accent-rsa",
        "ECDSA":   "key-accent-ecdsa",
    }

    # Map key type -> CSS badge modifier class
    _KEY_BADGE_MOD: dict[str, str] = {
        "ED25519": "ed25519",
        "RSA":     "rsa",
        "ECDSA":   "ecdsa",
    }

    def __init__(self, key_data: dict) -> None:
        super().__init__()
        self.key_data = key_data
        self.set_margin_start(5)
        self.set_margin_end(5)
        self.set_margin_top(5)
        self.set_margin_bottom(5)
        self.add_css_class("key-card")

        raw_type = key_data.get("key_type", "ED25519").upper()
        # Normalise RSA-2048, RSA-3072 etc. -> "RSA"
        type_key = next((k for k in self._KEY_ACCENT if raw_type.startswith(k)), None)

        # Outer horizontal container: left stripe + body
        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        outer.add_css_class("card")
        outer.set_size_request(210, -1)

        # Left color stripe
        stripe = Gtk.Box()
        stripe.add_css_class(
            self._KEY_ACCENT.get(type_key, "key-accent-default")
            if type_key else "key-accent-default"
        )
        outer.append(stripe)

        # Card body
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        body.set_hexpand(True)
        body.set_margin_start(11)
        body.set_margin_end(11)
        body.set_margin_top(11)
        body.set_margin_bottom(11)

        # Row 1: icon + name + type badge
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)

        icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        icon.set_pixel_size(16)
        icon.add_css_class("accent")
        row1.append(icon)

        name_lbl = Gtk.Label(label=key_data.get("label", "Unnamed Key"))
        name_lbl.set_halign(Gtk.Align.START)
        name_lbl.set_hexpand(True)
        name_lbl.add_css_class("heading")
        name_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        row1.append(name_lbl)

        badge = Gtk.Label(label=raw_type)
        badge.add_css_class("key-type-badge")
        badge.add_css_class(
            self._KEY_BADGE_MOD.get(type_key, "other")
            if type_key else "other"
        )
        row1.append(badge)
        body.append(row1)

        # Row 2: fingerprint (monospace background label, truncated)
        fp = key_data.get("fingerprint", "")
        fp_display = fp
        if len(fp) > 30:
            fp_display = fp[:14] + "…" + fp[-10:]
        fp_lbl = Gtk.Label(label=fp_display)
        fp_lbl.set_halign(Gtk.Align.START)
        fp_lbl.add_css_class("fingerprint-label")
        fp_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        body.append(fp_lbl)

        outer.append(body)
        self.set_child(outer)

class DetailRow(Gtk.ListBoxRow):
    def __init__(self, title: str) -> None:
        super().__init__()
        self.set_selectable(False)
        self.set_activatable(False)
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.set_margin_start(16)
        box.set_margin_end(16)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        
        title_lbl = Gtk.Label(label=title)
        title_lbl.set_halign(Gtk.Align.START)
        title_lbl.add_css_class("heading")
        box.append(title_lbl)
        
        self.value_lbl = Gtk.Label()
        self.value_lbl.set_halign(Gtk.Align.START)
        self.value_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        self.value_lbl.set_max_width_chars(38)
        self.value_lbl.add_css_class("caption")
        self.value_lbl.add_css_class("dim-label")
        box.append(self.value_lbl)
        
        self.set_child(box)

    def set_subtitle(self, text: str) -> None:
        self.value_lbl.set_label(text)



class KeychainPage(Gtk.Box):
    """The Keychain Page widget containing the key grid and management forms."""

    def __init__(self, parent_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL)
        self._parent = parent_window

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # Left Panel (Grid + Actions Bar)
        left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        left_box.set_hexpand(True)

        # Actions Bar
        actions_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions_bar.set_margin_start(16)
        actions_bar.set_margin_end(16)
        actions_bar.set_margin_top(12)
        actions_bar.set_margin_bottom(12)

        title_label = Gtk.Label(label=_("Keychain"))
        title_label.add_css_class("title-1")
        actions_bar.append(title_label)

        actions_spacer = Gtk.Box()
        actions_spacer.set_hexpand(True)
        actions_bar.append(actions_spacer)

        # + New Key button with dropdown
        new_key_btn = Gtk.MenuButton()
        new_key_btn.set_label(_("New Key"))
        new_key_btn.add_css_class("suggested-action")
        
        new_key_menu = Gio.Menu()
        new_key_menu.append(_("Generate Key"), "keychain.generate_key")
        new_key_menu.append(_("Import Key"), "keychain.import_key")
        new_key_btn.set_menu_model(new_key_menu)
        actions_bar.append(new_key_btn)

        # Setup SimpleActionGroup for dropdown actions
        action_group = Gio.SimpleActionGroup()
        generate_action = Gio.SimpleAction.new("generate_key", None)
        generate_action.connect("activate", lambda *_: self._show_generate_form())
        action_group.add_action(generate_action)

        import_action = Gio.SimpleAction.new("import_key", None)
        import_action.connect("activate", lambda *_: self._show_import_form())
        action_group.add_action(import_action)

        self.insert_action_group("keychain", action_group)
        left_box.append(actions_bar)

        # Main scroll area for grid
        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_margin_start(16)
        scroll.set_margin_end(16)
        scroll.set_margin_bottom(16)

        # Stack for empty state vs grid
        self._left_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.CROSSFADE,
            transition_duration=200,
        )

        # Grid view (FlowBox)
        self._flow_box = Gtk.FlowBox()
        self._flow_box.set_valign(Gtk.Align.START)
        self._flow_box.set_max_children_per_line(10)
        self._flow_box.set_min_children_per_line(1)
        self._flow_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._flow_box.connect("child-activated", self._on_key_selected)
        self._flow_box.connect("selected-children-changed", self._on_selection_changed)

        scroll.set_child(self._flow_box)
        self._left_stack.add_named(scroll, "grid")

        # Empty state
        empty_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            halign=Gtk.Align.CENTER,
            valign=Gtk.Align.CENTER,
            vexpand=True,
        )
        empty_icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        empty_icon.set_pixel_size(48)
        empty_icon.set_opacity(0.3)
        empty_box.append(empty_icon)

        empty_label = Gtk.Label(label=_("No Keys Stored"))
        empty_label.add_css_class("title-2")
        empty_box.append(empty_label)

        empty_desc = Gtk.Label(label=_("Generate or import SSH keys to associate with your hosts."))
        empty_desc.add_css_class("dim-label")
        empty_box.append(empty_desc)
        
        self._left_stack.add_named(empty_box, "empty")
        left_box.append(self._left_stack)

        self.append(left_box)

        # Separator
        self._sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        self.append(self._sep)

        # Right Panel (Forms / Details)
        self._right_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._right_panel.set_size_request(390, -1)
        self._right_panel.set_visible(True)

        # Clamp wrapper for right panel
        self._right_clamp = Adw.Clamp()
        self._right_clamp.set_maximum_size(390)
        self._right_clamp.set_child(self._right_panel)
        self._right_clamp.set_hexpand(False)
        self._right_clamp.set_halign(Gtk.Align.END)
        self._right_clamp.set_visible(False)

        # Right header with Close button
        right_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        right_header.set_margin_start(16)
        right_header.set_margin_end(16)
        right_header.set_margin_top(12)
        right_header.set_margin_bottom(12)

        self._right_title = Gtk.Label()
        self._right_title.add_css_class("title-2")
        right_header.append(self._right_title)

        right_spacer = Gtk.Box()
        right_spacer.set_hexpand(True)
        right_header.append(right_spacer)

        close_btn = Gtk.Button(icon_name="window-close-symbolic")
        close_btn.add_css_class("flat")
        close_btn.connect("clicked", lambda _: self._close_right_panel())
        right_header.append(close_btn)
        self._right_panel.append(right_header)

        # Stack inside Right Panel
        self._right_stack = Gtk.Stack(
            transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
            transition_duration=250,
        )
        self._right_stack.set_margin_start(16)
        self._right_stack.set_margin_end(16)
        self._right_stack.set_margin_bottom(16)

        # Build form pages
        self._build_generate_page()
        self._build_import_page()
        self._build_details_page()

        self._right_panel.append(self._right_stack)
        self.append(self._right_clamp)

    def _build_generate_page(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)

        pref_group = Adw.PreferencesGroup()
        
        # Label Entry
        self._gen_label_row = Adw.EntryRow(title=_("Label"))
        pref_group.add(self._gen_label_row)

        # Key Type selector (ComboRow)
        type_list = Gtk.StringList.new(["ED25519", "RSA-3072"])
        self._gen_type_row = Adw.ComboRow(title=_("Key Type"), model=type_list)
        pref_group.add(self._gen_type_row)

        # Passphrase
        self._gen_passphrase_row = Adw.PasswordEntryRow(title=_("Passphrase (optional)"))
        pref_group.add(self._gen_passphrase_row)
        
        box.append(pref_group)

        # Generate Button
        self._gen_btn = Gtk.Button(label=_("Generate & Save"))
        self._gen_btn.add_css_class("suggested-action")
        self._gen_btn.add_css_class("pill")
        self._gen_btn.connect("clicked", self._on_generate_clicked)
        box.append(self._gen_btn)

        # Loading Indicator
        self._gen_spinner = Gtk.Spinner()
        self._gen_spinner.set_halign(Gtk.Align.CENTER)
        box.append(self._gen_spinner)

        # Error label
        self._gen_error = Gtk.Label()
        self._gen_error.add_css_class("error")
        self._gen_error.set_visible(False)
        box.append(self._gen_error)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(box)
        self._right_stack.add_named(scroll, "generate")

    def _build_import_page(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)

        pref_group = Adw.PreferencesGroup()
        
        # Label Entry
        self._imp_label_row = Adw.EntryRow(title=_("Label"))
        pref_group.add(self._imp_label_row)

        # Passphrase Entry (in case private key is encrypted)
        self._imp_passphrase_row = Adw.PasswordEntryRow(title=_("Passphrase (if encrypted)"))
        pref_group.add(self._imp_passphrase_row)
        
        box.append(pref_group)

        # Import File button
        file_btn = Gtk.Button(label=_("Import from Key File"))
        file_btn.connect("clicked", self._on_import_file_clicked)
        box.append(file_btn)

        # Text area for pasted private key
        text_label = Gtk.Label(label=_("Or Paste Private Key PEM:"))
        text_label.set_halign(Gtk.Align.START)
        box.append(text_label)

        scroll_text = Gtk.ScrolledWindow(vexpand=True)
        scroll_text.set_size_request(-1, 150)
        self._imp_text_view = Gtk.TextView()
        self._imp_text_view.set_monospace(True)
        scroll_text.set_child(self._imp_text_view)
        box.append(scroll_text)

        # Save Button
        self._imp_btn = Gtk.Button(label=_("Import"))
        self._imp_btn.add_css_class("suggested-action")
        self._imp_btn.add_css_class("pill")
        self._imp_btn.connect("clicked", self._on_import_clicked)
        box.append(self._imp_btn)

        # Error label
        self._imp_error = Gtk.Label()
        self._imp_error.add_css_class("error")
        self._imp_error.set_visible(False)
        box.append(self._imp_error)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(box)
        self._right_stack.add_named(scroll, "import")

    def _build_details_page(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)

        pref_group = Adw.PreferencesGroup()

        # Type Row
        self._det_type_row = DetailRow(title=_("Type"))
        pref_group.add(self._det_type_row)

        # Fingerprint Row
        self._det_fp_row = DetailRow(title=_("Fingerprint"))
        pref_group.add(self._det_fp_row)

        box.append(pref_group)

        # Public Key Area
        pub_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        pub_label = Gtk.Label(label=_("Public Key (OpenSSH format)"))
        pub_label.set_halign(Gtk.Align.START)
        pub_header.append(pub_label)

        pub_spacer = Gtk.Box()
        pub_spacer.set_hexpand(True)
        pub_header.append(pub_spacer)

        pub_copy_btn = Gtk.Button(icon_name="edit-copy-symbolic")
        pub_copy_btn.add_css_class("flat")
        pub_copy_btn.set_tooltip_text(_("Copy Public Key"))
        pub_copy_btn.connect("clicked", self._on_copy_public_key)
        pub_header.append(pub_copy_btn)
        box.append(pub_header)

        scroll_pub = Gtk.ScrolledWindow()
        scroll_pub.set_size_request(-1, 80)
        self._det_pub_text = Gtk.TextView()
        self._det_pub_text.set_editable(False)
        self._det_pub_text.set_monospace(True)
        self._det_pub_text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroll_pub.set_child(self._det_pub_text)
        box.append(scroll_pub)

        # Private Key Area (hidden by default)
        priv_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        priv_label = Gtk.Label(label=_("Private Key"))
        priv_label.set_halign(Gtk.Align.START)
        priv_header.append(priv_label)

        priv_spacer = Gtk.Box()
        priv_spacer.set_hexpand(True)
        priv_header.append(priv_spacer)

        self._det_priv_toggle = Gtk.ToggleButton(icon_name="content-loading-symbolic") # eye/show icon
        self._det_priv_toggle.set_tooltip_text(_("Show/Hide Private Key"))
        self._det_priv_toggle.add_css_class("flat")
        self._det_priv_toggle.connect("toggled", self._on_priv_toggled)
        priv_header.append(self._det_priv_toggle)

        priv_copy_btn = Gtk.Button(icon_name="edit-copy-symbolic")
        priv_copy_btn.add_css_class("flat")
        priv_copy_btn.set_tooltip_text(_("Copy Private Key"))
        priv_copy_btn.connect("clicked", self._on_copy_private_key)
        priv_header.append(priv_copy_btn)
        box.append(priv_header)

        self._scroll_priv = Gtk.ScrolledWindow()
        self._scroll_priv.set_size_request(-1, 120)
        self._scroll_priv.set_visible(False)
        self._det_priv_text = Gtk.TextView()
        self._det_priv_text.set_editable(False)
        self._det_priv_text.set_monospace(True)
        self._scroll_priv.set_child(self._det_priv_text)
        box.append(self._scroll_priv)

        # Remove Key Button
        del_btn = Gtk.Button(label=_("Remove Key"))
        del_btn.add_css_class("destructive-action")
        del_btn.add_css_class("pill")
        del_btn.connect("clicked", self._on_delete_clicked)
        box.append(del_btn)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(box)
        self._right_stack.add_named(scroll, "details")

    # ── Grid Refresh & Handlers ───────────────────────────────

    def refresh(self) -> None:
        """Reload all keys from the vault and rebuild the flowbox."""
        # Check if the vault is unlocked. If not, don't query
        vm = VaultManager.get()
        if not vm.is_unlocked:
            self._left_stack.set_visible_child_name("empty")
            return

        # Clear existing grid
        while True:
            child = self._flow_box.get_child_at_index(0)
            if child is None:
                break
            self._flow_box.remove(child)

        try:
            keys = vm.list_global_keys()
        except Exception as e:
            logger.error(f"Keychain: Failed to list keys: {e}")
            keys = []

        if not keys:
            self._left_stack.set_visible_child_name("empty")
            return

        for k in keys:
            card = KeyCard(k)
            self._flow_box.append(card)
            self._setup_context_menu(card)

        self._left_stack.set_visible_child_name("grid")

    def _setup_context_menu(self, card: KeyCard) -> None:
        popover = Gtk.PopoverMenu()
        menu_model = Gio.Menu()
        menu_model.append(_("Remove"), "cardrow.remove")
        popover.set_menu_model(menu_model)
        popover.set_parent(card)
        popover.set_has_arrow(False)
        popover.set_position(Gtk.PositionType.BOTTOM)

        action_group = Gio.SimpleActionGroup()
        
        c_remove = Gio.SimpleAction.new("remove", None)
        c_remove.connect("activate", lambda *_: self._remove_key(card.key_data))
        action_group.add_action(c_remove)

        card.insert_action_group("cardrow", action_group)

        gesture = Gtk.GestureClick.new()
        gesture.set_button(Gdk.BUTTON_SECONDARY)
        
        def _on_right_click(gesture_obj, n_press, x, y):
            if not card.is_selected():
                self._flow_box.unselect_all()
                self._flow_box.select_child(card)
                self._show_details(card.key_data)

            rect = Gdk.Rectangle()
            rect.x, rect.y, rect.width, rect.height = int(x), int(y), 1, 1
            popover.set_pointing_to(rect)
            popover.popup()
            
        gesture.connect("pressed", _on_right_click)
        card.add_controller(gesture)

    def _on_key_selected(self, _flow_box: Gtk.FlowBox, card: KeyCard) -> None:
        self._show_details(card.key_data)

    def _on_selection_changed(self, _flow_box: Gtk.FlowBox) -> None:
        selected = self._flow_box.get_selected_children()
        if not selected:
            # If nothing is selected, we close details if we are on details page
            if self._right_stack.get_visible_child_name() == "details":
                self._close_right_panel()
        else:
            self._show_details(selected[0].key_data)

    # ── Right Panel Form Actions ──────────────────────────────

    def _show_generate_form(self) -> None:
        self._right_title.set_label(_("Generate New Key"))
        self._gen_label_row.set_text("")
        self._gen_type_row.set_selected(0) # ED25519
        self._gen_passphrase_row.set_text("")
        self._gen_error.set_visible(False)
        
        self._right_stack.set_visible_child_name("generate")
        self._right_clamp.set_visible(True)
        self._sep.set_visible(True)

    def _show_import_form(self) -> None:
        self._right_title.set_label(_("Import Key"))
        self._imp_label_row.set_text("")
        self._imp_passphrase_row.set_text("")
        buffer = self._imp_text_view.get_buffer()
        buffer.set_text("")
        self._imp_error.set_visible(False)

        self._right_stack.set_visible_child_name("import")
        self._right_clamp.set_visible(True)
        self._sep.set_visible(True)

    def _show_details(self, key_data: dict) -> None:
        self._selected_key = key_data
        self._right_title.set_label(key_data.get("label", "Key Details"))
        
        self._det_type_row.set_subtitle(key_data.get("key_type", "unknown"))
        self._det_fp_row.set_subtitle(key_data.get("fingerprint", "unknown"))

        # Public Key
        pub_buf = self._det_pub_text.get_buffer()
        pub_buf.set_text(key_data.get("public_key", ""))

        # Private Key (Keep hidden initially)
        self._det_priv_toggle.set_active(False)
        self._scroll_priv.set_visible(False)
        priv_buf = self._det_priv_text.get_buffer()
        priv_buf.set_text("") # Clear until shown

        self._right_stack.set_visible_child_name("details")
        self._right_clamp.set_visible(True)
        self._sep.set_visible(True)

    def _close_right_panel(self) -> None:
        self._right_clamp.set_visible(False)
        self._sep.set_visible(False)
        # Clear selected card selection
        self._flow_box.unselect_all()

    # ── Key Gen Logic ─────────────────────────────────────────

    def _on_generate_clicked(self, _btn: Gtk.Button) -> None:
        label = self._gen_label_row.get_text().strip()
        if not label:
            self._gen_error.set_label(_("Label is required."))
            self._gen_error.set_visible(True)
            return

        key_type_sel = self._gen_type_row.get_selected()
        key_type = "ED25519" if key_type_sel == 0 else "RSA"
        passphrase = self._gen_passphrase_row.get_text()

        # Start spinner
        self._gen_spinner.start()
        self._gen_btn.set_sensitive(False)
        self._gen_error.set_visible(False)

        # Run generation in a background thread to prevent UI freezing
        def _bg_generate():
            try:
                priv, pub, fp = generate_key_pair(key_type, passphrase)
                return True, priv, pub, fp
            except Exception as e:
                return False, str(e), "", ""

        def _on_done(result_tuple):
            success, priv, pub, fp = result_tuple
            self._gen_spinner.stop()
            self._gen_btn.set_sensitive(True)

            if success:
                # Save to Vault
                item_id = f"key_{uuid.uuid4().hex}"
                pass_sb = SecureBytes(passphrase) if passphrase else None
                try:
                    VaultManager.get().store_global_key(
                        item_id=item_id,
                        label=label,
                        private_key_pem=SecureBytes(priv),
                        public_key_openssh=pub,
                        key_type="Ed25519" if key_type == "ED25519" else "RSA-3072",
                        fingerprint=fp,
                        passphrase=pass_sb
                    )
                    if pass_sb:
                        pass_sb.clear()
                    self._show_toast(_("Generated and saved key '{name}'").format(name=label))
                    self.refresh()
                    self._close_right_panel()
                except Exception as e:
                    self._gen_error.set_label(_("Failed to save to vault: {e}").format(e=e))
                    self._gen_error.set_visible(True)
            else:
                self._gen_error.set_label(_("Generation failed: {msg}").format(msg=priv))
                self._gen_error.set_visible(True)

        # Threading wrapper
        def run_thread():
            res = _bg_generate()
            GLib.idle_add(lambda: _on_done(res) and False)

        import threading
        threading.Thread(target=run_thread, daemon=True).start()

    # ── Key Import Logic ──────────────────────────────────────

    def _on_import_file_clicked(self, _btn: Gtk.Button) -> None:
        """Open a file chooser to load a private key file."""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select Private Key File"))
        
        def _on_open_callback(dialog_obj, result):
            try:
                file_obj = dialog_obj.open_finish(result)
                path = file_obj.get_path()
                if path:
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    buffer = self._imp_text_view.get_buffer()
                    buffer.set_text(content)
                    # Pre-fill label if empty
                    import os
                    basename = os.path.basename(path)
                    if not self._imp_label_row.get_text():
                        self._imp_label_row.set_text(basename)
            except Exception as e:
                logger.error(f"Keychain: Failed to read key file: {e}")

        dialog.open(self._parent, None, _on_open_callback)

    def _on_import_clicked(self, _btn: Gtk.Button) -> None:
        label = self._imp_label_row.get_text().strip()
        if not label:
            self._imp_error.set_label(_("Label is required."))
            self._imp_error.set_visible(True)
            return

        passphrase = self._imp_passphrase_row.get_text()
        
        buffer = self._imp_text_view.get_buffer()
        start, end = buffer.get_bounds()
        priv_pem = buffer.get_text(start, end, True).strip()

        if not priv_pem:
            self._imp_error.set_label(_("Private key PEM is empty."))
            self._imp_error.set_visible(True)
            return

        self._imp_error.set_visible(False)
        try:
            pub, fp, k_type = extract_public_key_from_private(priv_pem, passphrase)
        except Exception as e:
            self._imp_error.set_label(str(e))
            self._imp_error.set_visible(True)
            return

        # Save to vault
        item_id = f"key_{uuid.uuid4().hex}"
        pass_sb = SecureBytes(passphrase) if passphrase else None
        try:
            VaultManager.get().store_global_key(
                item_id=item_id,
                label=label,
                private_key_pem=SecureBytes(priv_pem),
                public_key_openssh=pub,
                key_type=k_type,
                fingerprint=fp,
                passphrase=pass_sb
            )
            if pass_sb:
                pass_sb.clear()
            self._show_toast(_("Imported key '{name}'").format(name=label))
            self.refresh()
            self._close_right_panel()
        except Exception as e:
            self._imp_error.set_label(_("Failed to save to vault: {e}").format(e=e))
            self._imp_error.set_visible(True)

    # ── Key Details Actions ───────────────────────────────────

    def _on_priv_toggled(self, btn: Gtk.ToggleButton) -> None:
        show = btn.get_active()
        self._scroll_priv.set_visible(show)
        priv_buf = self._det_priv_text.get_buffer()
        
        if show:
            # Fetch private key from vault and decrypt it
            vm = VaultManager.get()
            k_id = self._selected_key["id"]
            k_data = vm.get_global_key(k_id)
            if k_data and k_data.get("private_key"):
                priv_buf.set_text(k_data["private_key"].unsafe_get_str())
            else:
                priv_buf.set_text(_("Failed to load private key."))
        else:
            priv_buf.set_text("") # Erase from UI memory

    def _on_copy_public_key(self, _btn: Gtk.Button) -> None:
        pub_key = self._selected_key.get("public_key", "")
        if pub_key:
            self.get_clipboard().set(pub_key)
            self._show_toast(_("Public key copied to clipboard."))

    def _on_copy_private_key(self, _btn: Gtk.Button) -> None:
        vm = VaultManager.get()
        k_id = self._selected_key["id"]
        k_data = vm.get_global_key(k_id)
        if k_data and k_data.get("private_key"):
            self.get_clipboard().set(k_data["private_key"].unsafe_get_str())
            self._show_toast(_("Private key copied to clipboard."))
        else:
            self._show_toast(_("Failed to copy private key."))

    def _remove_key(self, key_data: dict) -> None:
        k_id = key_data["id"]
        k_label = key_data["label"]

        dialog = Adw.AlertDialog(
            heading=_("Remove Key '{name}'?").format(name=k_label),
            body=_("This key pair will be permanently removed from the vault."),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("remove", _("Remove"))
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def _on_response(_d, response):
            if response == "remove":
                VaultManager.get().delete_item(k_id)
                self._show_toast(_("Removed: {name}").format(name=k_label))
                self.refresh()
                if getattr(self, "_selected_key", None) and self._selected_key.get("id") == k_id:
                    self._close_right_panel()

        dialog.connect("response", _on_response)
        dialog.present(self._parent)

    def _on_delete_clicked(self, _btn: Gtk.Button) -> None:
        if self._selected_key:
            self._remove_key(self._selected_key)

    # ── Toast / Overlay ───────────────────────────────────────

    def _show_toast(self, msg: str) -> None:
        if hasattr(self._parent, "_show_toast"):
            self._parent._show_toast(msg)
        else:
            logger.info(f"Toast: {msg}")
