# SPDX-License-Identifier: GPL-3.0-or-later

"""Dialog implementations for SSH authentication (Password, Host Key)."""

import asyncio
import json
import os
import subprocess
from typing import Callable
import gettext
from gi.repository import Adw, Gtk, GLib, Gdk, Gio
from utils.secure import SecureBytes

_ = gettext.gettext


def prompt_password(
    parent: Gtk.Window,
    title: str,
    subtitle: str,
    callback: Callable[[SecureBytes | None, bool], None] | Callable[[SecureBytes | None], None],
    show_remember: bool = False
) -> None:
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
    
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.append(entry)
    
    remember_check = None
    if show_remember:
        remember_check = Gtk.CheckButton(label=_("Remember password"))
        remember_check.set_margin_top(6)
        box.append(remember_check)
    
    # Enter key behavior
    def _on_activate(_e: Gtk.Entry) -> None:
        dialog.response("ok")
    entry.connect("activate", _on_activate)
    
    dialog.set_extra_child(box)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        if response == "ok":
            if show_remember:
                remember = remember_check.get_active() if remember_check else False
                callback(SecureBytes(entry.get_text()), remember)
            else:
                callback(SecureBytes(entry.get_text()))
        else:
            if show_remember:
                callback(None, False)
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
        self._header.set_show_start_title_buttons(False)
        self._header.set_show_end_title_buttons(False)
        self._toolbar.add_top_bar(self._header)
 
        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.add_css_class("flat")
        cancel_btn.connect("clicked", lambda _: self._finish(None, ""))
        self._header.pack_start(cancel_btn)

        # Title widget stack to switch between standard title and search entry
        self._title_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        
        self._title_label = Gtk.Label(label=_("Select SSH Key from Vault"))
        self._title_label.add_css_class("title")
        self._title_stack.add_named(self._title_label, "title")
        
        self._search_entry = Gtk.SearchEntry()
        self._search_entry.set_placeholder_text(_("Search keys…"))
        self._search_entry.set_hexpand(True)
        self._search_entry.set_size_request(240, -1)
        self._search_entry.connect("search-changed", self._on_search_changed)
        self._search_entry.connect("stop-search", lambda _: self._stop_search())
        self._search_entry.connect("activate", self._on_search_entry_activated)
        self._title_stack.add_named(self._search_entry, "search")
        
        self._header.set_title_widget(self._title_stack)

        # Search button
        self._search_btn = Gtk.Button(icon_name="edit-find-symbolic")
        self._search_btn.add_css_class("flat")
        self._search_btn.connect("clicked", lambda _: self._start_search())
        self._header.pack_end(self._search_btn)

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

        # Key event controller for direct typing
        key_controller = Gtk.EventControllerKey()
        key_controller.connect("key-pressed", self._on_window_key_pressed)
        self.add_controller(key_controller)

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
        
        # Apply search filter if active
        if self._title_stack.get_visible_child_name() == "search":
            self._on_search_changed(self._search_entry)

    def _start_search(self, initial_text: str = "") -> None:
        self._title_stack.set_visible_child_name("search")
        self._search_btn.set_visible(False)
        if initial_text:
            self._search_entry.set_text(initial_text)
            self._search_entry.set_position(-1)
        self._search_entry.grab_focus()

    def _stop_search(self) -> None:
        self._search_entry.set_text("")
        self._title_stack.set_visible_child_name("title")
        self._search_btn.set_visible(True)
        self._list_box.grab_focus()

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        text = entry.get_text().lower()
        row = self._list_box.get_first_child()
        while row:
            if isinstance(row, Adw.ActionRow):
                title = (row.get_title() or "").lower()
                subtitle = (row.get_subtitle() or "").lower()
                row.set_visible(text in title or text in subtitle)
            row = row.get_next_sibling()

    def _on_search_entry_activated(self, _entry) -> None:
        row = self._list_box.get_first_child()
        while row:
            if isinstance(row, Adw.ActionRow) and row.get_visible():
                self._on_row_activated(self._list_box, row)
                break
            row = row.get_next_sibling()

    def _on_window_key_pressed(self, controller, keyval, keycode, state) -> bool:
        if self._search_entry.is_focus():
            return False
            
        if self._main_stack.get_visible_child_name() != "content":
            return False
            
        modifiers = (
            Gdk.ModifierType.CONTROL_MASK |
            Gdk.ModifierType.ALT_MASK |
            Gdk.ModifierType.META_MASK
        )
        if state & modifiers:
            return False
            
        unicode_char = Gdk.keyval_to_unicode(keyval)
        if unicode_char == 0:
            return False
            
        char = chr(unicode_char)
        if char.isprintable() and not char.isspace():
            self._start_search(char)
            return True
            
        return False

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


class AppChooserReplica(Adw.Window):
    """Custom application chooser that looks like the system one but is internal."""
    
    def __init__(self, parent: Gtk.Window, filename: str, mime_type: str, callback: Callable[[Gio.AppInfo | None], None]) -> None:
        super().__init__(modal=True, transient_for=parent)
        self.set_title(_("Open {f}").format(f=filename))
        self.set_default_size(420, 520)
        
        self._callback = callback
        self._done = False
        
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Header
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)
        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda _: self._finish(None))
        header.pack_start(cancel_btn)
        
        open_btn = Gtk.Button(label=_("Open"))
        open_btn.add_css_class("suggested-action")
        open_btn.connect("clicked", self._on_open_clicked)
        header.pack_end(open_btn)
        self._open_btn = open_btn
        self._open_btn.set_sensitive(False)
        
        box.append(header)
        
        # Search Entry (Filtering only)
        search_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        search_box.set_margin_top(12)
        search_box.set_margin_bottom(12)
        search_box.set_margin_start(12)
        search_box.set_margin_end(12)
        
        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text(_("Search applications…"))
        search_box.append(search_entry)
        
        box.append(search_box)
        self._search_entry = search_entry
        
        # List of apps
        scroll = Gtk.ScrolledWindow(vexpand=True)
        self._list_box = Gtk.ListBox()
        self._list_box.add_css_class("boxed-list")
        self._list_box.set_margin_start(12)
        self._list_box.set_margin_end(12)
        self._list_box.set_margin_bottom(12)
        self._list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._list_box.connect("row-activated", lambda *_: self._on_open_clicked())
        self._list_box.connect("selected-rows-changed", self._on_selection_changed)
        
        scroll.set_child(self._list_box)
        box.append(scroll)
        
        box.append(scroll)
        self.set_content(box)
        
        # Load apps
        self._load_apps(mime_type)
        
        # Filtering
        search_entry.connect("search-changed", self._on_search_changed)
        
    def _load_apps(self, mime_type: str) -> None:
        from gi.repository import Gio
        
        # 1. Get standard sandbox visible apps
        recommended = Gio.AppInfo.get_all_for_type(mime_type)
        all_apps = Gio.AppInfo.get_all()
        
        # 2. Try to fetch Host-side applications if in Flatpak
        host_apps = []
        try:
            # Using the Gio approach recommended by the developer (it's cleaner and handles translations)
            # We run it on the host to see all host-registered apps.
            host_cmd = [
                "flatpak-spawn", "--host", "python3", "-c",
                "import gi, json; gi.require_version('Gio', '2.0'); from gi.repository import Gio; "
                "apps=[{'name': a.get_name(), 'icon': a.get_icon().to_string() if a.get_icon() else None, 'exec': a.get_commandline()} "
                "for a in Gio.AppInfo.get_all() if a.should_show()]; "
                "print(json.dumps(apps))"
            ]
            
            GLib.idle_add(lambda: print("Sentinel: Scanning host-side applications via Gio..."))
            proc = subprocess.Popen(host_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            
            if err:
                err_msg = err.decode()
                GLib.idle_add(lambda: print(f"Sentinel: Host-scan diagnostic: {err_msg}"))
                
            if out:
                host_apps = json.loads(out.decode())
                n = len(host_apps)
                GLib.idle_add(lambda: print(f"Sentinel: Discovered {n} host applications."))
            else:
                GLib.idle_add(lambda: print("Sentinel: Host-scan returned no applications."))
        except Exception as e:
            err_str = str(e)
            GLib.idle_add(lambda: print(f"Sentinel: Host-scan system error: {err_str}"))

        # Deduplicate and sort: Recommended first
        seen_names = set()
        
        # 1. Recommended Apps section (Sandbox)
        if recommended:
            self._add_section_header(_("Recommended Apps"))
            for app in recommended:
                name = app.get_name()
                if name in seen_names: continue
                seen_names.add(name)
                self._add_app_row(app)

        # 2. Host Applications section (Crucial for "Arbitrary Application" freedom)
        if host_apps:
            # Filter out standard ones to show meaningful Host-only ones
            to_add = []
            for ha in host_apps:
                if ha['name'] in seen_names: continue
                # Basic filtering of known "dumb" utilities or duplicates
                if ha['name'] in ("Settings", "Files", "Terminal", "Help"): continue
                to_add.append(ha)
                
            if to_add:
                self._add_section_header(_("Host Applications"))
                # Sort Host apps
                to_add.sort(key=lambda x: x['name'].lower())
                for ha in to_add:
                    if ha['name'] in seen_names: continue
                    seen_names.add(ha['name'])
                    # We wrap the host command as a dummy AppInfo
                    # Strip % vars from exec
                    clean_exec = ha['exec'].split(' %')[0].replace('"', '').strip()
                    app = Gio.AppInfo.create_from_commandline(clean_exec, ha['name'], Gio.AppInfoCreateFlags.NONE)
                    self._add_app_row(app, custom_icon=ha['icon'])

        # 3. Add any remaining Sandbox Apps
        self._add_section_header(_("Other Sandbox Apps"))
        others = sorted(
            [a for a in all_apps if a.get_name() not in seen_names], 
            key=lambda x: x.get_name().lower()
        )
        for app in others:
            self._add_app_row(app)

    def _add_section_header(self, text: str) -> None:
        header_row = Gtk.ListBoxRow(selectable=False, activatable=False)
        header_row.set_child(Gtk.Label(label=text, xalign=0, margin_top=12, margin_bottom=6))
        header_row.add_css_class("dim-label")
        header_row.add_css_class("caption")
        header_row.set_margin_start(12)
        self._list_box.append(header_row)

    def _add_app_row(self, app: Gio.AppInfo, custom_icon: str | None = None) -> None:
        row = Adw.ActionRow(title=app.get_name(), subtitle=app.get_description() or "")
        
        # Icon handling (Best effort)
        icon_widget = None
        if custom_icon:
            if "/" in custom_icon:
                # It's a path, but in sandbox it might not resolve.
                # However, many host paths for icons are in /usr/share/icons
                icon_widget = Gtk.Image.new_from_icon_name(os.path.basename(custom_icon).split(".")[0])
            else:
                icon_widget = Gtk.Image.new_from_icon_name(custom_icon)
        
        if not icon_widget or icon_widget.get_icon_name() is None:
            gicon = app.get_icon()
            if gicon:
                icon_widget = Gtk.Image.new_from_gicon(gicon)
            else:
                icon_widget = Gtk.Image.new_from_icon_name("application-x-executable-symbolic")
                
        icon_widget.set_pixel_size(32)
        row.add_prefix(icon_widget)
        
        setattr(row, "_app_info", app)
        self._list_box.append(row)

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        text = entry.get_text().lower()
        row = self._list_box.get_first_child()
        while row:
            if isinstance(row, Adw.ActionRow):
                title = row.get_title().lower()
                row.set_visible(text in title)
            row = row.get_next_sibling()

    def _on_selection_changed(self, lb: Gtk.ListBox) -> None:
        row = lb.get_selected_row()
        self._open_btn.set_sensitive(row is not None and isinstance(row, Adw.ActionRow))

    def _on_open_clicked(self, *args) -> None:
        row = self._list_box.get_selected_row()
        if row and isinstance(row, Adw.ActionRow):
            self._finish(getattr(row, "_app_info", None))

    def _finish(self, app_info: Gio.AppInfo | None) -> None:
        if not self._done:
            self._done = True
            self._callback(app_info)
            self.destroy()


def confirm_sync_removals(
    parent: Gtk.Window,
    removals: list[str],
    resolve: Callable[[bool], None]
) -> None:
    """Prompt the user to confirm the removal of local items during sync."""
    dialog = Adw.MessageDialog(
        heading=_("Confirm Sync Removals"),
        body=_("The cloud configuration does not contain some local items. The following items (and a total of {count} items) will be removed:\n\n{items}").format(
            count=len(removals),
            items="\n".join(f"• {item}" for item in removals[:5]) + ("\n• ..." if len(removals) > 5 else "")
        )
    )
    dialog.add_response("cancel", _("Cancel"))
    dialog.add_response("confirm", _("Remove"))
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_modal(True)
    
    if parent:
        real_parent = parent if isinstance(parent, Gtk.Window) else parent.get_root()
        if isinstance(real_parent, Gtk.Window):
            dialog.set_transient_for(real_parent)

    def _on_response(d: Adw.MessageDialog, response: str) -> None:
        resolve(response == "confirm")
        d.destroy()

    dialog.connect("response", _on_response)
    dialog.present()


