# SPDX-License-Identifier: GPL-3.0-or-later

"""Dialog implementations for SSH authentication (Password, Host Key)."""

import asyncio
from typing import Callable
import gettext
from gi.repository import Adw, Gtk, GLib, Gdk
from utils.secure import SecureBytes

_ = gettext.gettext


def prompt_password(parent: Gtk.Window, title: str, subtitle: str, callback: Callable[[SecureBytes | None], None]) -> None:
    """Prompt the user for a password or passphrase."""
    dialog = Adw.MessageDialog(
        heading=title,
        body=subtitle,
    )
    dialog.add_response("cancel", _("Cancel"))
    dialog.add_response("ok", _("Connect"))
    dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("ok")
    dialog.set_close_response("cancel")
    dialog.set_modal(True)

    # Use Gtk.Entry with password purpose for better clipboard compatibility on some systems
    entry = Gtk.Entry()
    entry.set_visibility(False)
    entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
    entry.set_margin_top(12)
    
    # Enter key behavior
    def _on_activate(_e: Gtk.Entry) -> None:
        dialog.response("ok")
    entry.connect("activate", _on_activate)
    
    dialog.set_extra_child(entry)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        if response == "ok":
            callback(SecureBytes(entry.get_text()))
        else:
            callback(None)
        # Explicitly destroy to ensure it leaves the screen
        d.destroy()
        
    dialog.connect("response", _on_response)
    
    if parent:
        # Get the actual root window if parent is just a widget
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    
    dialog.present()
    
    # Delay grab_focus slightly to ensure the window is mapped, fixing Paste grayed out
    GLib.timeout_add(100, lambda: entry.grab_focus() and False)


def prompt_host_key(
    parent: Gtk.Window,
    hostname: str, 
    fingerprint: str, 
    algorithm: str,
    callback: Callable[[bool], None]
) -> None:
    """Ask the user to verify a new SSH host key."""
    dialog = Adw.MessageDialog(
        heading=_("Unknown Host Key ({hostname})").format(hostname=hostname),
        body=(
            _("The authenticity of host '{hostname}' can't be established.\n\n").format(hostname=hostname) +
            _("Algorithm: {algorithm}\n").format(algorithm=algorithm) +
            _("Fingerprint: {fingerprint}\n\n").format(fingerprint=fingerprint) +
            _("Are you sure you want to continue connecting?")
        )
    )
    dialog.add_response("no", _("Reject"))
    dialog.add_response("yes", _("Accept and Connect"))
    dialog.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        callback(response == "yes")
        d.destroy()
        
    dialog.connect("response", _on_response)
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    dialog.present()


def prompt_vault_unlock(
    parent: Gtk.Window,
    vault_name: str,
    callback: Callable[[str | None], None]
) -> None:
    """Prompt the user for the vault's master password."""
    dialog = Adw.MessageDialog(
        heading=_("Unlock {vault_name}").format(vault_name=vault_name),
        body=_("Please enter your master password to access {vault_name} credentials.").format(vault_name=vault_name)
    )
    dialog.add_response("cancel", _("Cancel"))
    dialog.add_response("ok", _("Unlock"))
    dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("ok")
    dialog.set_modal(True)

    entry = Gtk.Entry()
    entry.set_visibility(False)
    entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
    entry.set_margin_top(12)
    entry.connect("activate", lambda _: dialog.response("ok"))
    dialog.set_extra_child(entry)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        if response == "ok":
            callback(SecureBytes(entry.get_text()))
        else:
            callback(None)
        d.destroy()
        
    dialog.connect("response", _on_response)
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    dialog.present()
    GLib.timeout_add(100, lambda: entry.grab_focus() and False)


def prompt_vault_item_selection(
    parent: Gtk.Window,
    items: list,  # list[VaultCredential]
    callback: Callable[[str | None], None],
) -> None:
    """Legacy API: ask user to select a vault credential (delegates to prompt_vault_key_selection)."""
    def _wrapped(item_id: str | None, _name: str) -> None:
        callback(item_id)
    prompt_vault_key_selection(parent, items, _wrapped)


class VaultKeyPickerDialog(Adw.Window):
    """Standalone modal window for selecting a vault SSH key item (with loading state)."""
    
    def __init__(self, parent: Gtk.Window, callback: Callable[[str | None, str], None]) -> None:
        super().__init__()
        self._callback = callback
        self._done = False
        
        self.set_title(_("Select SSH Key from Vault"))
        self.set_default_size(420, 480)
        self.set_resizable(True)
        self.set_modal(True)
        if parent:
            real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
            if isinstance(real_parent, Gtk.Window):
                self.set_transient_for(real_parent)

        # UI Components
        self._toolbar = Adw.ToolbarView()
        self._header = Adw.HeaderBar()
        self._toolbar.add_top_bar(self._header)
 
        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.add_css_class("flat")
        cancel_btn.connect("clicked", lambda _: self._finish(None, ""))
        self._header.pack_start(cancel_btn)

        # Main Layout
        self._main_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        
        # 1. Loading State
        loading_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER, spacing=12)
        self._spinner = Gtk.Spinner()
        self._spinner.set_size_request(32, 32)
        loading_box.append(self._spinner)
        loading_box.append(Gtk.Label(label=_("Retrieving data from Vault...")))
        self._main_stack.add_named(loading_box, "loading")
        
        # 2. Content State
        self._content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._content_box.set_margin_top(12)
        self._content_box.set_margin_bottom(12)
        self._content_box.set_margin_start(12)
        self._content_box.set_margin_end(12)
        
        hint = Gtk.Label(
            label=_("Choose the vault item that contains the SSH private key for this connection."),
            wrap=True, xalign=0,
        )
        hint.add_css_class("dim-label")
        hint.add_css_class("caption")
        hint.set_margin_bottom(8)
        self._content_box.append(hint)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        self._list_box = Gtk.ListBox()
        self._list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list_box.set_activate_on_single_click(True)
        self._list_box.add_css_class("boxed-list")
        self._list_box.connect("row-activated", self._on_row_activated)
        
        scroll.set_child(self._list_box)
        self._content_box.append(scroll)
        self._main_stack.add_named(self._content_box, "content")
        
        # Assemble
        self._toolbar.set_content(self._main_stack)
        self.set_content(self._toolbar)
        self.connect("close-request", lambda _: self._finish(None, "") and False)

        # Start loading
        self._main_stack.set_visible_child_name("loading")
        self._spinner.start()

    def set_items(self, items: list) -> None:
        """Populate items and switch to content view."""
        # Clear existing
        while row := self._list_box.get_first_child():
            self._list_box.remove(row)
            
        for item in items:
            subtitle = item.username or ""
            if item.note:
                 subtitle = f"{subtitle} • {item.note}" if subtitle else item.note
                 
            row = Adw.ActionRow(title=item.name, subtitle=subtitle)
            row.set_activatable(True)
            
            if item.has_ssh_key:
                key_icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
                key_icon.set_opacity(0.8)
                row.add_suffix(key_icon)
 
            select_btn = Gtk.Button(label=_("Select"))
            select_btn.add_css_class("suggested-action")
            select_btn.add_css_class("flat")
            select_btn.set_valign(Gtk.Align.CENTER)
            
            # Use closures carefully
            i_id, i_name = item.item_id, item.name
            select_btn.connect("clicked", lambda _, i=i_id, n=i_name: self._finish(i, n))
            row.add_suffix(select_btn)

            setattr(row, "_item_id", item.item_id)
            setattr(row, "_item_name", item.name)
            self._list_box.append(row)

        self._spinner.stop()
        self._main_stack.set_visible_child_name("content")

    def _on_row_activated(self, _lb, row: Adw.ActionRow) -> None:
        self._finish(getattr(row, "_item_id", None), getattr(row, "_item_name", ""))

    def _finish(self, item_id: str | None, item_name: str) -> None:
        if not self._done:
            self._done = True
            self._callback(item_id, item_name)
            self.destroy()


def prompt_vault_key_selection(
    parent: Gtk.Window,
    items: list | None,
    callback: Callable[[str | None, str], None],
) -> VaultKeyPickerDialog:
    """Show a standalone modal window for selecting a vault SSH key item (returns dialog)."""
    dialog = VaultKeyPickerDialog(parent, callback)
    dialog.present()
    if items is not None:
        dialog.set_items(items)
    return dialog


def prompt_entry(
    parent: Gtk.Window,
    title: str,
    body: str,
    initial_text: str,
    placeholder: str,
    callback: Callable[[str | None], None],
) -> None:
    """Prompt the user for a single line of text."""
    dialog = Adw.MessageDialog(heading=title, body=body)
    dialog.add_response("cancel", _("Cancel"))
    dialog.add_response("ok", _("Confirm"))
    dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("ok")
    dialog.set_close_response("cancel")
    dialog.set_modal(True)

    entry = Gtk.Entry(text=initial_text, placeholder_text=placeholder)
    entry.set_margin_top(12)
    entry.connect("activate", lambda _: dialog.response("ok"))
    dialog.set_extra_child(entry)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        if response == "ok":
            # If this is used for sensitive data in the future, we should decide if it returns SecureBytes
            # For now, it's used for hostname etc. so str is fine. 
            # But let's check one specific use case: if it's used for Vault passphrase.
            callback(entry.get_text())
        else:
            callback(None)
        d.destroy()

    dialog.connect("response", _on_response)
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    dialog.present()
    GLib.timeout_add(100, lambda: entry.grab_focus() and False)


def prompt_confirmation(
    parent: Gtk.Window,
    title: str,
    body: str,
    confirm_label: str,
    is_destructive: bool,
    callback: Callable[[bool], None],
) -> None:
    """Ask for confirmation."""
    dialog = Adw.MessageDialog(heading=title, body=body)
    dialog.add_response("no", _("Cancel"))
    dialog.add_response("yes", confirm_label)
    if is_destructive:
        dialog.set_response_appearance("yes", Adw.ResponseAppearance.DESTRUCTIVE)
    else:
        dialog.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("no")
    dialog.set_close_response("no")

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        callback(response == "yes")
        d.destroy()

    dialog.connect("response", _on_response)
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    dialog.present()



def show_info(parent: Gtk.Window, title: str, body: str) -> None:
    """Show an information dialog."""
    dialog = Adw.MessageDialog(heading=title, body=body)
    dialog.add_response("ok", _("OK"))
    dialog.set_default_response("ok")
    dialog.set_close_response("ok")

    def _on_response(d: Adw.MessageDialog, _response: str) -> None:
        d.destroy()

    dialog.connect("response", _on_response)
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)
    dialog.present()


class FilePropertiesDialog(Adw.Window):
    """A detailed file properties dialog with copy-to-clipboard support."""
    
    def __init__(self, parent: Gtk.Window, file_info: dict) -> None:
        super().__init__()
        self.set_title(_("Properties: {name}").format(name=file_info.get('name', _('File'))))
        self.set_default_size(400, -1)
        self.set_modal(True)
        self.set_resizable(False)
        
        if parent:
            real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
            if isinstance(real_parent, Gtk.Window):
                self.set_transient_for(real_parent)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        header = Adw.HeaderBar()
        content.append(header)

        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        list_box.add_css_class("boxed-list")
        list_box.set_margin_start(12)
        list_box.set_margin_end(12)
        list_box.set_margin_top(12)
        list_box.set_margin_bottom(12)
        
        # Helper to add rows
        def add_row(label, value, copy_val=None):
            row = Adw.ActionRow(title=label, subtitle=str(value))
            row.set_activatable(True)
            
            # Click to copy behavior
            def on_activated(_):
                clipboard = Gdk.Display.get_default().get_clipboard()
                clipboard.set_text(copy_val or str(value))
                # toast?
                # For now just print/debug
                pass

            row.connect("activated", on_activated)
            
            # Copy icon as suffix
            copy_icon = Gtk.Image.new_from_icon_name("edit-copy-symbolic")
            copy_icon.set_opacity(0.5)
            row.add_suffix(copy_icon)
            
            list_box.append(row)

        add_row(_("Name"), file_info.get("name"))
        add_row(_("Type"), _("Directory") if file_info.get("is_dir") else _("File"))
        add_row(_("Size"), file_info.get("size_str"))
        add_row(_("Last Modified"), file_info.get("mtime_str"))
        add_row(_("Permissions"), file_info.get("permissions_oct"), file_info.get("permissions_oct"))
        add_row(_("Owner"), _("UID: {uid} / GID: {gid}").format(uid=file_info.get('uid'), gid=file_info.get('gid')))
        add_row(_("Remote Path"), file_info.get("path"), file_info.get("path"))

        content.append(list_box)
        
        # Close button at bottom
        close_btn = Gtk.Button(label=_("Close"))
        close_btn.set_margin_start(12)
        close_btn.set_margin_end(12)
        close_btn.set_margin_bottom(12)
        close_btn.set_margin_top(0)
        close_btn.connect("clicked", lambda _: self.destroy())
        content.append(close_btn)

        self.set_content(content)

def show_file_properties(parent: Gtk.Window, file_info: dict) -> None:
    """Show the new detailed file properties dialog."""
    dialog = FilePropertiesDialog(parent, file_info)
    dialog.present()

