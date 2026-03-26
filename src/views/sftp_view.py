# SPDX-License-Identifier: GPL-3.0-or-later

"""SFTP file browser view."""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

import gettext
from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango, Vte, GObject  # noqa: E402

_ = gettext.gettext

from models.connection import Connection
from services.ssh_service import SSHService

logger = logging.getLogger(__name__)


class SftpFile(GObject.Object):
    """GObject representing a file in SFTP."""
    
    name = GObject.Property(type=str, default="")
    size = GObject.Property(type=int, default=0)
    mtime = GObject.Property(type=int, default=0)
    is_dir = GObject.Property(type=bool, default=False)
    permissions = GObject.Property(type=int, default=0)
    uid = GObject.Property(type=int, default=0)
    gid = GObject.Property(type=int, default=0)

    def __init__(self, name: str, size: int, mtime: int, is_dir: bool, permissions: int, uid: int=0, gid: int=0) -> None:
        super().__init__(
            name=name,
            size=size,
            mtime=mtime,
            is_dir=is_dir,
            permissions=permissions,
            uid=uid,
            gid=gid
        )

    @property
    def icon_name(self) -> str:
        if self.is_dir:
            return "folder-symbolic"
        return "text-x-generic-symbolic"

    @property
    def size_str(self) -> str:
        if self.is_dir:
            return "--"
        size = float(self.size)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024
        return f"{size:.1f} PB"

    @property
    def mtime_str(self) -> str:
        dt = datetime.fromtimestamp(self.mtime)
        return dt.strftime("%Y-%m-%d %H:%M")


class SftpTab(Gtk.Box):
    """A single SFTP tab with a file browser."""

    def __init__(
        self,
        connection: Connection,
        ssh_service: SSHService,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self._connection = connection
        self._ssh_service = ssh_service
        self._on_close = on_close
        
        self._sftp: Any = None
        self._ssh_conn: Any = None
        self._auth_info: dict[str, Any] = {}
        self._current_path = "."
        self._history: list[str] = []
        self._history_index = -1
        self._monitors: dict[str, Gio.FileMonitor] = {}
        self._pending_prompts: set[str] = set() # local_path
        self._initial_states: dict[str, tuple[float, int]] = {} # local_path -> (mtime, size)
        self._active_edits: dict[str, str] = {} # remote_path -> local_path
        
        import tempfile
        self._temp_dir = tempfile.mkdtemp(prefix="sentinel_edit_{id}_".format(id=connection.id))
        
        self._show_hidden = False
        self._auto_sync = False
        self._all_items: list[SftpFile] = []  # Local cache of all items in current dir
        
        self._file_store = Gio.ListStore.new(SftpFile)
        self._build_ui()
        self._connect_sftp()

    def _build_ui(self) -> None:
        # Toolbar
        header_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        header_bar.add_css_class("toolbar")
        header_bar.set_margin_top(4)
        header_bar.set_margin_bottom(4)

        # Back / Forward
        self._back_btn = Gtk.Button(icon_name="go-previous-symbolic")
        self._back_btn.set_sensitive(False)
        self._back_btn.connect("clicked", self._on_back_clicked)
        header_bar.append(self._back_btn)

        self._forward_btn = Gtk.Button(icon_name="go-next-symbolic")
        self._forward_btn.set_sensitive(False)
        self._forward_btn.connect("clicked", self._on_forward_clicked)
        header_bar.append(self._forward_btn)

        # Up
        self._up_btn = Gtk.Button(icon_name="go-up-symbolic")
        self._up_btn.connect("clicked", self._on_up_clicked)
        header_bar.append(self._up_btn)

        # Refresh
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.connect("clicked", lambda _: self._load_path(self._current_path))
        header_bar.append(refresh_btn)

        # New... Menu
        self._new_btn = Gtk.MenuButton(icon_name="list-add-symbolic", tooltip_text=_("New..."))
        new_menu = Gio.Menu()
        new_menu.append(_("New File"), "sftp.new-file")
        new_menu.append(_("New Folder"), "sftp.new-folder")
        self._new_btn.set_menu_model(new_menu)
        header_bar.append(self._new_btn)

        # Path entry
        self._path_entry = Gtk.Entry(hexpand=True)
        self._path_entry.connect("activate", self._on_path_entry_activated)
        header_bar.append(self._path_entry)

        # View Options (Nautilus style)
        self._view_opts_btn = Gtk.MenuButton(icon_name="view-more-symbolic", tooltip_text=_("View Options"))
        self._view_opts_menu = Gio.Menu()
        
        # Section for filters
        filter_section = Gio.Menu()
        filter_section.append(_("Show Hidden Files"), "sftp.show-hidden")
        self._view_opts_menu.append_section(None, filter_section)
        
        # Section for edit behavior
        edit_section = Gio.Menu()
        edit_section.append(_("Auto-sync on Save"), "sftp.auto-sync")
        self._view_opts_menu.append_section(None, edit_section)
        
        self._view_opts_btn.set_menu_model(self._view_opts_menu)
        header_bar.append(self._view_opts_btn)

        self.append(header_bar)

        # File List (ColumnView)
        self._column_view = Gtk.ColumnView()
        self._column_view.set_hexpand(True)
        self._column_view.set_vexpand(True)
        self._column_view.add_css_class("sftp-file-list")
        
        # ── Drop Target (Accepting items IN) ──────
        # We add this to the view itself. Gdk.FileList for OS files, str for internal URIs.
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
        drop_target.set_gtypes([Gdk.FileList, str, GLib.Bytes])
        drop_target.connect("enter", self._on_drop_enter)
        drop_target.connect("leave", self._on_drop_leave)
        drop_target.connect("drop", self._on_drop)
        self._column_view.add_controller(drop_target)
        
        # Selection
        self._sorter = self._column_view.get_sorter()
        self._sort_model = Gtk.SortListModel.new(self._file_store, self._sorter)
        self._selection_model = Gtk.SingleSelection(model=self._sort_model)
        self._column_view.set_model(self._selection_model)
        
        # Double click to open
        self._column_view.connect("activate", self._on_row_activated)

        # Columns
        # Icon + Name
        name_factory = Gtk.SignalListItemFactory()
        name_factory.connect("setup", self._setup_name_column)
        name_factory.connect("bind", self._bind_name_column)
        name_col = Gtk.ColumnViewColumn(title=_("Name"), factory=name_factory)
        name_col.set_expand(True)
        name_col.set_resizable(True)
        
        # Name Sorter: Directories first, then alphabetical
        def _name_compare(a, b, *args):
            # Dirs first
            if a.props.is_dir != b.props.is_dir:
                return Gtk.Ordering.SMALLER if a.props.is_dir else Gtk.Ordering.LARGER
            # Then name case-insensitive
            an, bn = a.props.name.lower(), b.props.name.lower()
            if an < bn: return Gtk.Ordering.SMALLER
            if an > bn: return Gtk.Ordering.LARGER
            return Gtk.Ordering.EQUAL

        name_sorter = Gtk.CustomSorter.new(_name_compare)
        name_col.set_sorter(name_sorter)
        self._column_view.append_column(name_col)
        
        # Default sort by name column
        self._column_view.sort_by_column(name_col, Gtk.SortType.ASCENDING)

        # Size
        size_factory = Gtk.SignalListItemFactory()
        size_factory.connect("setup", self._setup_text_column)
        size_factory.connect("bind", self._bind_size_column)
        size_col = Gtk.ColumnViewColumn(title=_("Size"), factory=size_factory)
        size_col.set_fixed_width(100)
        size_col.set_resizable(True)
        
        def _size_compare(a, b, *args):
            if a.props.is_dir != b.props.is_dir:
                return Gtk.Ordering.SMALLER if a.props.is_dir else Gtk.Ordering.LARGER
            if a.props.size < b.props.size: return Gtk.Ordering.SMALLER
            if a.props.size > b.props.size: return Gtk.Ordering.LARGER
            return Gtk.Ordering.EQUAL

        size_sorter = Gtk.CustomSorter.new(_size_compare)
        size_col.set_sorter(size_sorter)
        self._column_view.append_column(size_col)

        # Time
        time_factory = Gtk.SignalListItemFactory()
        time_factory.connect("setup", self._setup_text_column)
        time_factory.connect("bind", self._bind_time_column)
        time_col = Gtk.ColumnViewColumn(title=_("Date Modified"), factory=time_factory)
        time_col.set_fixed_width(160)
        time_col.set_resizable(True)
        
        def _time_compare(a, b, *args):
            if a.props.is_dir != b.props.is_dir:
                return Gtk.Ordering.SMALLER if a.props.is_dir else Gtk.Ordering.LARGER
            if a.props.mtime < b.props.mtime: return Gtk.Ordering.SMALLER
            if a.props.mtime > b.props.mtime: return Gtk.Ordering.LARGER
            return Gtk.Ordering.EQUAL

        time_sorter = Gtk.CustomSorter.new(_time_compare)
        time_col.set_sorter(time_sorter)
        self._column_view.append_column(time_col)

        scroll = Gtk.ScrolledWindow(vexpand=True)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Context Menu
        self._menu_model = Gio.Menu()
        self._menu_model.append(_("Edit"), "sftp.edit")
        self._menu_model.append(_("Open With..."), "sftp.open-with")
        self._menu_model.append(_("Copy"), "sftp.copy")
        self._menu_model.append(_("Paste"), "sftp.paste")
        self._menu_model.append(_("Synchronize"), "sftp.sync")
        self._menu_model.append(_("Download"), "sftp.download")
        self._menu_model.append(_("Calculate Size"), "sftp.calculate-size")
        # Danger zone
        danger_section = Gio.Menu()
        danger_section.append(_("Rename"), "sftp.rename")
        danger_section.append(_("Delete"), "sftp.delete")
        danger_section.append(_("Properties"), "sftp.properties")
        self._menu_model.append_section(None, danger_section)

        self._action_group = Gio.SimpleActionGroup.new()
        
        edit_action = Gio.SimpleAction.new("edit", None)
        edit_action.connect("activate", lambda *_: self._edit_selected())
        self._action_group.add_action(edit_action)

        copy_action = Gio.SimpleAction.new("copy", None)
        copy_action.connect("activate", lambda *_: self._copy_selected())
        self._action_group.add_action(copy_action)

        paste_action = Gio.SimpleAction.new("paste", None)
        paste_action.connect("activate", lambda *_: self._paste_from_clipboard())
        self._action_group.add_action(paste_action)

        sync_action = Gio.SimpleAction.new("sync", None)
        sync_action.connect("activate", lambda *_: self._force_sync_selected())
        self._action_group.add_action(sync_action)

        download_action = Gio.SimpleAction.new("download", None)
        download_action.connect("activate", lambda *_: self._download_selected())
        self._action_group.add_action(download_action)

        rename_action = Gio.SimpleAction.new("rename", None)
        rename_action.connect("activate", lambda *_: self._rename_selected())
        self._action_group.add_action(rename_action)

        delete_action = Gio.SimpleAction.new("delete", None)
        delete_action.connect("activate", lambda *_: self._delete_selected())
        self._action_group.add_action(delete_action)

        open_with_action = Gio.SimpleAction.new("open-with", None)
        open_with_action.connect("activate", lambda *_: self._open_with_selected())
        self._action_group.add_action(open_with_action)

        new_file_action = Gio.SimpleAction.new("new-file", None)
        new_file_action.connect("activate", lambda *_: self._on_new_file_clicked())
        self._action_group.add_action(new_file_action)

        new_folder_action = Gio.SimpleAction.new("new-folder", None)
        new_folder_action.connect("activate", lambda *_: self._on_mkdir_clicked(None))
        self._action_group.add_action(new_folder_action)

        # Toggle actions
        show_hidden_action = Gio.SimpleAction.new_stateful(
            "show-hidden", None, GLib.Variant.new_boolean(self._show_hidden)
        )
        show_hidden_action.connect("activate", self._on_toggle_show_hidden)
        self._action_group.add_action(show_hidden_action)

        auto_sync_action = Gio.SimpleAction.new_stateful(
            "auto-sync", None, GLib.Variant.new_boolean(self._auto_sync)
        )
        auto_sync_action.connect("activate", self._on_toggle_auto_sync)
        self._action_group.add_action(auto_sync_action)

        properties_action = Gio.SimpleAction.new("properties", None)
        properties_action.connect("activate", lambda *_: self._on_properties_selected())
        self._action_group.add_action(properties_action)

        calc_size_action = Gio.SimpleAction.new("calculate-size", None)
        calc_size_action.connect("activate", lambda *_: self._on_calculate_size())
        self._action_group.add_action(calc_size_action)

        self.insert_action_group("sftp", self._action_group)

        self._popover = Gtk.PopoverMenu.new_from_model(self._menu_model)
        self._popover.set_parent(self._column_view)
        self._popover.set_has_arrow(False)

        click_gesture = Gtk.GestureClick.new()
        click_gesture.set_button(Gdk.BUTTON_SECONDARY)
        click_gesture.connect("pressed", self._on_right_click)
        self._column_view.add_controller(click_gesture)

        # Shortcuts
        shortcut_ctrl = Gtk.ShortcutController.new()
        shortcut_ctrl.set_scope(Gtk.ShortcutScope.MANAGED)
        
        # Primary actions
        copy_trigger = Gtk.ShortcutTrigger.parse_string("<Control>c")
        copy_shortcut = Gtk.Shortcut.new(copy_trigger, Gtk.CallbackAction.new(self._on_copy_shortcut))
        shortcut_ctrl.add_shortcut(copy_shortcut)
        
        paste_trigger = Gtk.ShortcutTrigger.parse_string("<Control>v")
        paste_shortcut = Gtk.Shortcut.new(paste_trigger, Gtk.CallbackAction.new(self._on_paste_shortcut))
        shortcut_ctrl.add_shortcut(paste_shortcut)
        
        rename_trigger = Gtk.ShortcutTrigger.parse_string("F2")
        rename_shortcut = Gtk.Shortcut.new(rename_trigger, Gtk.CallbackAction.new(lambda *_: self._rename_selected()))
        shortcut_ctrl.add_shortcut(rename_shortcut)

        delete_trigger = Gtk.ShortcutTrigger.parse_string("Delete")
        delete_shortcut = Gtk.Shortcut.new(delete_trigger, Gtk.CallbackAction.new(lambda *_: self._delete_selected()))
        shortcut_ctrl.add_shortcut(delete_shortcut)
        
        mkdir_trigger = Gtk.ShortcutTrigger.parse_string("<Control><Shift>n")
        mkdir_shortcut = Gtk.Shortcut.new(mkdir_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_mkdir_clicked(None), True)[1]))
        shortcut_ctrl.add_shortcut(mkdir_shortcut)

        # Alt Navigation Shortcuts
        up_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>Up")
        up_shortcut = Gtk.Shortcut.new(up_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_up_clicked(None), True)[1]))
        shortcut_ctrl.add_shortcut(up_shortcut)

        back_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>Left")
        back_shortcut = Gtk.Shortcut.new(back_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_back_clicked(None), True)[1]))
        shortcut_ctrl.add_shortcut(back_shortcut)

        forward_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>Right")
        forward_shortcut = Gtk.Shortcut.new(forward_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_forward_clicked(None), True)[1]))
        shortcut_ctrl.add_shortcut(forward_shortcut)

        # Other Alt/F shortcuts
        props_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>Return")
        props_shortcut = Gtk.Shortcut.new(props_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_properties_selected(), True)[1]))
        shortcut_ctrl.add_shortcut(props_shortcut)

        edit_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>e")
        edit_shortcut = Gtk.Shortcut.new(edit_trigger, Gtk.CallbackAction.new(lambda *_: (self._edit_selected(), True)[1]))
        shortcut_ctrl.add_shortcut(edit_shortcut)

        calc_trigger = Gtk.ShortcutTrigger.parse_string("<Alt>s")
        calc_shortcut = Gtk.Shortcut.new(calc_trigger, Gtk.CallbackAction.new(lambda *_: (self._on_calculate_size(), True)[1]))
        shortcut_ctrl.add_shortcut(calc_shortcut)

        refresh_trigger = Gtk.ShortcutTrigger.parse_string("F5")
        refresh_shortcut = Gtk.Shortcut.new(refresh_trigger, Gtk.CallbackAction.new(lambda *_: (self._load_path(self._current_path), True)[1]))
        shortcut_ctrl.add_shortcut(refresh_shortcut)

        path_trigger = Gtk.ShortcutTrigger.parse_string("<Control>l")
        path_shortcut = Gtk.Shortcut.new(path_trigger, Gtk.CallbackAction.new(lambda *_: (self._path_entry.grab_focus(), True)[1]))
        shortcut_ctrl.add_shortcut(path_shortcut)

        self.add_controller(shortcut_ctrl)

        # Status Bar
        self._status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._status_bar.add_css_class("toolbar")

        # Status Bar Icon Stack (Spinner or Checkmark)
        self._status_icon_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        
        self._spinner = Gtk.Spinner()
        self._status_icon_stack.add_named(self._spinner, "spinner")
        
        self._check_icon = Gtk.Image.new_from_icon_name("object-select-symbolic")
        self._check_icon.add_css_class("success")  # optional styling
        self._status_icon_stack.add_named(self._check_icon, "check")
        
        self._status_bar.append(self._status_icon_stack)
 
        self._status_label = Gtk.Label(label=_("Connecting…"), xalign=0, hexpand=True)
        self._status_label.add_css_class("dim-label")
        self._status_label.add_css_class("caption")
        self._status_bar.append(self._status_label)
        self.append(self._status_bar)

    def _setup_dnd(self) -> None:
        """Configure Drag and Drop for the file list."""
        # 1. Drag Source (Moving items OUT) - now handled per-item in column factories

        # 2. Drop Target (Accepting items IN)
        # We accept FileList (from OS) and String (sentinel-sftp:// URIs)
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
        drop_target.set_gtypes([Gdk.FileList, str])
        drop_target.connect("accept", self._on_drop_accept)
        drop_target.connect("enter", self._on_drop_enter)
        drop_target.connect("leave", self._on_drop_leave)
        drop_target.connect("drop", self._on_drop)
        self._column_view.add_controller(drop_target)

    # ── Drag & Drop Handlers ───────────────────────────────────

    def _on_drag_prepare(self, source: Gtk.DragSource, x: float, y: float) -> Gdk.ContentProvider | None:
        """Create a robust content provider for drag-and-drop."""
        file_obj = getattr(source, "item", None)
        if not file_obj:
            return None

        # 1. Internal protocol URI
        internal_uri = f"sentinel-sftp://{self._connection.id}{os.path.join(self._current_path, file_obj.name)}"
        
        # 2. Check for local mount (Rclone)
        from services.rclone_service import RcloneService
        rclone = RcloneService.get()
        
        providers = []
        
        # Internal custom type to avoid text fragmentation in Nautilus
        providers.append(Gdk.ContentProvider.new_for_bytes(
            "application/x-sentinel-internal-uri", 
            GLib.Bytes.new(internal_uri.encode("utf-8"))
        ))

        uri_list = []
        if rclone.is_mounted(self._connection.id):
            mount_path = rclone.get_mount_path(self._connection.id)
            rel_path = self._current_path.lstrip("/")
            local_path = os.path.join(mount_path, rel_path, file_obj.name)
            
            # Gdk.FileList is the GOLD standard for Nautilus integration
            try:
                gfile = Gio.File.new_for_path(local_path)
                file_list = Gdk.FileList.new_from_list([gfile])
                providers.append(Gdk.ContentProvider.new_for_value(file_list))
                
                import urllib.parse
                uri_list.append(f"file://{urllib.parse.quote(local_path)}")
            except Exception as e:
                logger.warning(f"Failed to create Gdk.FileList: {e}")

        # Standard text/uri-list (Nautilus fallback)
        uri_list.append(internal_uri)
        uri_list_str = "\r\n".join(uri_list) + "\r\n"
        providers.append(Gdk.ContentProvider.new_for_bytes(
            "text/uri-list", 
            GLib.Bytes.new(uri_list_str.encode("utf-8"))
        ))

        return Gdk.ContentProvider.new_union(providers)

    def _on_drag_begin(self, source: Gtk.DragSource, drag: Gdk.Drag) -> None:
        """Set the drag icon safely."""
        file_obj = getattr(source, "item", None)
        if not file_obj:
            return
            
        try:
            icon_name = file_obj.icon_name
            display = Gdk.Display.get_default()
            theme = Gtk.IconTheme.get_for_display(display)
            # Use symbolic icon search as fallback
            paintable = theme.lookup_icon(icon_name, None, 32, 1, Gtk.TextDirection.NONE, 0)
            if paintable:
                source.set_icon(paintable, 0, 0)
        except Exception as e:
            logger.warning(f"Failed to set drag icon: {e}")

    def _on_drop_accept(self, target: Gtk.DropTarget, drop: Gdk.Drop) -> bool:
        """Filter acceptable drop types."""
        return True

    def _on_drop_enter(self, target: Gtk.DropTarget, x: float, y: float) -> Gdk.DragAction:
        """Highlight UI when dragging over."""
        self._column_view.add_css_class("drag-over")
        return Gdk.DragAction.COPY

    def _on_drop_leave(self, target: Gtk.DropTarget) -> None:
        """Remove highlight."""
        self._column_view.remove_css_class("drag-over")

    def _on_drop(self, target: Gtk.DropTarget, value: Any, x: float, y: float) -> bool:
        """Handle the dropped data by triggering transfers or uploads."""
        self._column_view.remove_css_class("drag-over")
        
        # Internal URI via custom type (sent as bytes)
        if isinstance(value, GLib.Bytes):
            try:
                text = value.get_data().decode("utf-8")
                self._handle_paste_text(text)
                return True
            except: pass

        if isinstance(value, Gdk.FileList):
            files = value.get_files()
            if files:
                uris = "\n".join([f.get_uri() for f in files])
                self._handle_paste_text(uris)
                return True
        elif isinstance(value, str):
            self._handle_paste_text(value)
            return True
            
        return False

    # ── Column Factories ──────────────────────────────────────

    def _setup_name_column(self, factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        
        # Add Drag Source to the row-box
        drag_source = Gtk.DragSource.new()
        drag_source.set_actions(Gdk.DragAction.COPY | Gdk.DragAction.MOVE)
        drag_source.connect("prepare", self._on_drag_prepare)
        drag_source.connect("drag-begin", self._on_drag_begin)
        box.add_controller(drag_source)
        # Store controller on widget for retrieval in bind
        box.drag_source = drag_source # type: ignore
        
        icon = Gtk.Image()
        label = Gtk.Label(ellipsize=Pango.EllipsizeMode.END, xalign=0)
        
        box.append(icon)
        box.append(label)
        list_item.set_child(box)

    def _bind_name_column(self, factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        file_obj = list_item.get_item()
        box = list_item.get_child()
        # Update current item for the drag source (for recycling)
        if hasattr(box, "drag_source"):
            box.drag_source.item = file_obj # type: ignore
            
        icon = box.get_first_child()
        label = icon.get_next_sibling()
        
        icon.set_from_icon_name(file_obj.icon_name)
        label.set_text(file_obj.name)

    def _setup_text_column(self, factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        label = Gtk.Label(xalign=0)
        label.set_margin_start(8)
        label.set_margin_end(8)
        list_item.set_child(label)

    def _bind_size_column(self, factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        file_obj = list_item.get_item()
        label = list_item.get_child()
        label.set_text(file_obj.size_str)
        label.set_xalign(1) # Right align size

    def _bind_time_column(self, factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem) -> None:
        file_obj = list_item.get_item()
        label = list_item.get_child()
        label.set_text(file_obj.mtime_str)

    # ── SFTP Integration ──────────────────────────────────────

    def _connect_sftp(self) -> None:
        from views.dialogs import prompt_password, prompt_host_key, prompt_vault_unlock, prompt_vault_item_selection, prompt_entry, prompt_confirmation
        
        def _ask_password(conn, resolve):
            prompt_password(self.get_root(), _("Password for {hostname}").format(hostname=conn.hostname), "{username}@{hostname}".format(username=conn.username, hostname=conn.hostname), resolve)
        def _ask_passphrase(key_path, resolve):
            prompt_password(self.get_root(), _("Unlock SSH Key"), _("Enter passphrase for {path}").format(path=key_path), resolve)
        def _ask_host_key(hostname, fingerprint, alg, resolve):
            prompt_host_key(self.get_root(), hostname, fingerprint, alg, resolve)
        def _ask_vault_unlock(vault_name, resolve):
            from services.vault_service import VaultService
            def _on_password(password):
                if password:
                    async def do_unlock():
                        success = await VaultService.get().active_backend.unlock(password)
                        resolve(success)
                    self._ssh_service.engine.run_coroutine(do_unlock())
                else: resolve(False)
            prompt_vault_unlock(self.get_root(), vault_name, _on_password)
        def _ask_vault_item(items, resolve):
            prompt_vault_item_selection(self.get_root(), items, resolve)

        def _on_error(msg):
            def _set_err():
                self._status_label.set_label(msg)
                self._set_loading(False)
            GLib.idle_add(_set_err)

        callbacks = {
            "ask_password": _ask_password,
            "ask_passphrase": _ask_passphrase,
            "ask_host_key": _ask_host_key,
            "ask_vault_unlock": _ask_vault_unlock,
            "ask_vault_item": _ask_vault_item,
            "on_error": _on_error,
        }

        self._set_loading(True)

        async def _run():
            res = await self._ssh_service.start_sftp_session(self._connection, callbacks, status_cb=self._status_label.set_label)
            if res:
                self._sftp, self._ssh_conn, self._auth_info = res
                # Get real current path
                self._current_path = await self._sftp.getcwd()
                GLib.idle_add(self._on_sftp_connected)
            else:
                GLib.idle_add(lambda: self._set_loading(False))
        
        self._bg_task = self._ssh_service.engine.run_coroutine(_run())

    def _set_loading(self, is_loading: bool) -> None:
        if is_loading:
            self._spinner.start()
            self._status_icon_stack.set_visible_child_name("spinner")
        else:
            self._spinner.stop()
            self._status_icon_stack.set_visible_child_name("check")

    def _on_sftp_connected(self) -> None:
        self._status_label.set_label(_("Connected to {hostname}").format(hostname=self._connection.hostname))
        self._load_path(self._current_path)
        
        # Trigger background mount early to prepare for copy/paste
        async def _mount():
            from services.rclone_service import RcloneService
            uri, err = await RcloneService.get().mount(self._connection, self._auth_info)
            if err:
                logger.error(f"Background rclone mount failed: {err}")
                # We don't alert the user yet, only if they try to use it
        self._ssh_service.engine.run_coroutine(_mount())

    def _load_path(self, path: str) -> None:
        logger.info(f"SFTP: Loading path: {path}")
        self._status_label.set_label(_("Loading {path}…").format(path=path))
        self._set_loading(True)
        
        async def _fetch():
            try:
                # Absolute path if possible
                real_path = await self._sftp.realpath(path)
                # readdir returns SFTPName objects (filename, longname, attrs)
                attrs = await self._sftp.readdir(real_path)
                logger.info(f"SFTP: Fetched {len(attrs)} items for {real_path}")
                
                # Sort: dirs first, then name
                attrs.sort(key=lambda x: (not stat.S_ISDIR(x.attrs.permissions or 0), x.filename.lower()))
                
                def _update_ui():
                    logger.debug(f"SFTP: Updating UI with {len(attrs)} items")
                    self._all_items = []
                    for a in attrs:
                        if a.filename in ('.', '..'): continue
                        f = SftpFile(
                            name=a.filename,
                            size=a.attrs.size or 0,
                            mtime=a.attrs.mtime or 0,
                            is_dir=stat.S_ISDIR(a.attrs.permissions or 0),
                            permissions=a.attrs.permissions or 0,
                            uid=a.attrs.uid or 0,
                            gid=a.attrs.gid or 0
                        )
                        self._all_items.append(f)
                    
                    self._current_path = real_path
                    self._path_entry.set_text(real_path)
                    self._update_history(real_path)
                    self._refresh_store() # Call refresh_store to apply filters
                    self._set_loading(False)
                    logger.debug("SFTP: UI update complete")
                    
                GLib.idle_add(_update_ui)
            except Exception as e:
                err_msg = str(e)
                def _on_fetch_error():
                    self._status_label.set_label(_("Error: {msg}").format(msg=err_msg))
                    self._set_loading(False)
                GLib.idle_add(_on_fetch_error)
        
        if self._sftp:
            self._bg_task = self._ssh_service.engine.run_coroutine(_fetch())
        else:
            self._set_loading(False)

    # ── History ───────────────────────────────────────────────

    def _update_history(self, path: str) -> None:
        if self._history_index >= 0 and self._history[self._history_index] == path:
            return
        
        # Clear forward history
        self._history = self._history[:self._history_index+1]
        self._history.append(path)
        self._history_index = len(self._history) - 1
        
        self._update_nav_buttons()

    def _update_nav_buttons(self) -> None:
        self._back_btn.set_sensitive(self._history_index > 0)
        self._forward_btn.set_sensitive(self._history_index < len(self._history) - 1)

    # ── Handlers ──────────────────────────────────────────────

    def _on_back_clicked(self, _btn) -> None:
        if self._history_index > 0:
            self._history_index -= 1
            self._load_path(self._history[self._history_index])

    def _on_forward_clicked(self, _btn) -> None:
        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            self._load_path(self._history[self._history_index])

    def _on_up_clicked(self, _btn) -> None:
        parent = os.path.dirname(self._current_path)
        if parent != self._current_path:
            self._load_path(parent)

    def _on_path_entry_activated(self, entry: Gtk.Entry) -> None:
        self._load_path(entry.get_text())

    def _on_mkdir_clicked(self, _btn) -> None:
        from views.dialogs import prompt_entry
        def _on_done(name: str | None):
            if not name: return
            path = os.path.join(self._current_path, name)
            self._set_loading(True)
            self._status_label.set_label(_("Creating folder {name}...").format(name=name))
            
            async def _bg_mkdir():
                try:
                    await self._sftp.mkdir(path)
                    GLib.idle_add(self._on_transfer_finish, True, _("Created folder {name}").format(name=name))
                except Exception as e:
                    logger.error(f"Mkdir failed: {e}")
                    GLib.idle_add(self._on_transfer_finish, False, _("Error: {e}").format(e=e))
            
            self._bg_task = self._ssh_service.engine.run_coroutine(_bg_mkdir())

        prompt_entry(
            self.get_root(),
            _("New Folder"),
            _("Enter name for the new folder:"),
            _("New Folder"),
            _("Folder name"),
            _on_done
        )

    def _on_new_file_clicked(self) -> None:
        from views.dialogs import prompt_entry
        def _on_done(name: str | None):
            if not name: return
            path = os.path.join(self._current_path, name)
            self._set_loading(True)
            self._status_label.set_label(_("Creating file {name}...").format(name=name))
            
            async def _bg_mkfile():
                try:
                    # Create empty file
                    async with self._sftp.open(path, 'w') as f:
                        pass
                    GLib.idle_add(self._on_transfer_finish, True, _("Created file {name}").format(name=name))
                except Exception as e:
                    logger.error(f"File creation failed: {e}")
                    GLib.idle_add(self._on_transfer_finish, False, _("Error: {e}").format(e=e))
            
            self._bg_task = self._ssh_service.engine.run_coroutine(_bg_mkfile())

        prompt_entry(
            self.get_root(),
            _("New File"),
            _("Enter name for the new file:"),
            "new_file.txt",
            _("File name"),
            _on_done
        )

    def _on_row_activated(self, view: Gtk.ColumnView, position: int) -> None:
        file_obj = self._file_store.get_item(position)
        if not file_obj:
            return
        if file_obj.is_dir:
            new_path = os.path.join(self._current_path, file_obj.name)
            self._load_path(new_path)
        else:
            self._edit_selected()

    # ── Context & Transfer ──────────────────────────────────────

    def _on_right_click(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        # Dynamic menu sensitivity
        pos = self._selection_model.get_selected()
        has_selection = pos != Gtk.INVALID_LIST_POSITION
        
        # Dynamic state for actions
        calc_action = self._action_group.lookup_action("calculate-size")
        if calc_action:
            # Only enable calculate-size if a directory is selected
            is_dir = False
            if has_selection:
                file_obj = self._file_store.get_item(pos)
                if file_obj and file_obj.props.is_dir:
                    is_dir = True
            calc_action.set_enabled(is_dir)

        file_obj = self._file_store.get_item(pos) if has_selection else None
        
        is_file = file_obj is not None and not file_obj.is_dir
        
        # Check if monitored
        is_monitored = False
        if is_file:
            from services.rclone_service import RcloneService
            mount_path = RcloneService.get().get_mount_path(self._connection.id)
            local_path = os.path.join(mount_path, self._current_path.lstrip("/"), file_obj.name)
            is_monitored = local_path in self._monitors

        # Update action sensitivity
        self._action_group.lookup_action("edit").set_enabled(is_file)
        self._action_group.lookup_action("open-with").set_enabled(is_file)
        self._action_group.lookup_action("sync").set_enabled(is_monitored)
        self._action_group.lookup_action("copy").set_enabled(has_selection)
        self._action_group.lookup_action("rename").set_enabled(has_selection)
        self._action_group.lookup_action("delete").set_enabled(has_selection)
        self._action_group.lookup_action("download").set_enabled(has_selection)

        rect = Gdk.Rectangle()
        rect.x = int(x)
        rect.y = int(y)
        rect.width = 1
        rect.height = 1
        self._popover.set_pointing_to(rect)
        self._popover.popup()

    def _on_copy_shortcut(self, widget: Gtk.Widget, args: Any) -> bool:
        return self._copy_selected()

    def _on_paste_shortcut(self, widget: Gtk.Widget, args: Any) -> bool:
        return self._paste_from_clipboard()

    def _copy_selected(self) -> bool:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return False
        file_obj = self._file_store.get_item(pos)
        if not file_obj:
            return False

        import urllib.parse
        full_path = os.path.join(self._current_path, file_obj.name)
        internal_uri = f"sentinel-sftp://{self._connection.id}{full_path}"
        
        host = self._connection.hostname
        port = self._connection.port
        user = self._connection.username

        authority = f"{host}:{port}" if port != 22 else host
        if user:
            authority = f"{urllib.parse.quote(user)}@{authority}"
            
        encoded_path = urllib.parse.quote(full_path)
        gvfs_uri = f"sftp://{authority}{encoded_path}"

        # Rootless FUSE3 mount strategy using Rclone
        self._cache_and_copy_file(file_obj, internal_uri, gvfs_uri)
        return True

    def _cache_and_copy_file(self, file_obj: SftpFile, internal_uri: str, gvfs_fallback_uri: str) -> None:
        from services.rclone_service import RcloneService
        
        self._set_loading(True)
        self._status_label.set_label(_("Ensuring Rclone FUSE3 mount..."))
        
        async def _bg_mount():
            rclone = RcloneService.get()
            mount_uri, error = await rclone.mount(self._connection, self._auth_info)
            
            def _done():
                self._set_loading(False)
                if mount_uri:
                    import urllib.parse
                    import os
                    # Actually get the file path within the mount
                    mount_path = rclone.get_mount_path(self._connection.id)
                    real_path = os.path.join(mount_path, self._current_path.lstrip("/"), file_obj.name)
                    file_uri = f"file://{urllib.parse.quote(real_path)}"
                    self._set_clipboard_union(internal_uri, file_uri, file_obj.name)
                else:
                    logger.error(f"Failed to mount via Rclone: {error}")
                    # Fallback to GVFS URI if mount failed
                    self._status_label.set_label(_("Mount failed, using GVFS fallback. (Error: {err}...)").format(err=error[:30]))
                    self._set_clipboard_union(internal_uri, gvfs_fallback_uri, file_obj.name)
                    
            GLib.idle_add(_done)
            
        self._bg_task = self._ssh_service.engine.run_coroutine(_bg_mount())

    def _set_clipboard_union(self, internal_uri: str, external_uri: str, name: str) -> None:
        prov_text = Gdk.ContentProvider.new_for_value(internal_uri)
        prov_uri_list = Gdk.ContentProvider.new_for_bytes("text/uri-list", GLib.Bytes.new(external_uri.encode() + b"\r\n"))
        
        union = Gdk.ContentProvider.new_union([prov_text, prov_uri_list])
        self.get_clipboard().set_content(union)
        self._status_label.set_label(_("Copied {name} to clipboard").format(name=name))

    def _rename_selected(self) -> bool:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return False
        file_obj = self._file_store.get_item(pos)
        if not file_obj:
            return False

        from views.dialogs import prompt_entry
        def _on_rename(new_name: str | None):
            if not new_name or new_name == file_obj.name:
                return
            
            old_path = os.path.join(self._current_path, file_obj.name)
            new_path = os.path.join(self._current_path, new_name)
            
            self._set_loading(True)
            self._status_label.set_label(_("Renaming to {name}...").format(name=new_name))
            
            async def _bg_rename():
                try:
                    await self._sftp.rename(old_path, new_path)
                    GLib.idle_add(self._on_transfer_finish, True, _("Renamed to {name}").format(name=new_name))
                except Exception as e:
                    logger.error(f"Rename failed: {e}")
                    GLib.idle_add(self._on_transfer_finish, False, _("Rename failed: {e}").format(e=e))
            
            self._bg_task = self._ssh_service.engine.run_coroutine(_bg_rename())

        prompt_entry(
            self.get_root(),
            _("Rename Item"),
            _("Enter new name for {name}:").format(name=file_obj.name),
            file_obj.name,
            _("New name"),
            _on_rename
        )
        return True

    def _edit_selected(self) -> None:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION: return
        file_obj = self._file_store.get_item(pos)
        if not file_obj or file_obj.is_dir: return

        from services.rclone_service import RcloneService
        rclone = RcloneService.get()
        
        self._set_loading(True)
        self._status_label.set_label(_("Ensuring mount for editing..."))
        
        async def _mount_and_open():
            logger.info("SFTP Edit: Triggering rclone mount...")
            mount_uri, error = await rclone.mount(self._connection, self._auth_info)
            logger.info(f"SFTP Edit: Mount result: {mount_uri}, error: {error}")
            if not mount_uri:
                logger.warning(f"SFTP Edit: Mount failed ({error}), falling back to direct SFTP download.")
                # Fallback to direct download
                remote_path = os.path.join(self._current_path, file_obj.name)
                import uuid
                session_id = str(uuid.uuid4())[:8]
                edit_session_dir = os.path.join(self._temp_dir, session_id)
                os.makedirs(edit_session_dir, exist_ok=True)
                local_path = os.path.join(edit_session_dir, file_obj.name)
                
                try:
                    await self._sftp.get(remote_path, local_path)
                    GLib.idle_add(lambda: _launch(local_path, remote_path, file_obj.name))
                except Exception as e:
                    logger.error(f"Fallback download failed: {e}")
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Fallback failed: {e}").format(e=e))))
                return
            
            mount_path = rclone.get_mount_path(self._connection.id)
            mounted_file = os.path.join(mount_path, self._current_path.lstrip("/"), file_obj.name)
            remote_path = os.path.join(self._current_path, file_obj.name)
            
            # Local copy with original name in unique sub-dir
            import uuid
            session_id = str(uuid.uuid4())[:8]
            edit_session_dir = os.path.join(self._temp_dir, session_id)
            os.makedirs(edit_session_dir, exist_ok=True)
            local_path = os.path.join(edit_session_dir, file_obj.name)
            
            # Use a small wait to ensure rclone has populated the file entry
            import asyncio
            import shutil
            for _ in range(25):
                if os.path.exists(mounted_file): break
                await asyncio.sleep(0.2)
            
            if not os.path.exists(mounted_file):
                # Another fallback if mount exists but file is invisible
                logger.warning(f"File {file_obj.name} not visible in mount, attempting direct download.")
                try:
                    await self._sftp.get(remote_path, local_path)
                    GLib.idle_add(lambda: _launch(local_path, remote_path, file_obj.name))
                except Exception as e:
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Download failed: {e}").format(e=e))))
                return

            # Copy to temp edit location
            try:
                await asyncio.to_thread(shutil.copy2, mounted_file, local_path)
            except Exception as e:
                logger.error(f"Copy from mount failed: {e}, trying direct download.")
                try:
                    await self._sftp.get(remote_path, local_path)
                except Exception as ef:
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Download failed: {e}").format(e=ef))))
                    return

            GLib.idle_add(lambda: _launch(local_path, remote_path, file_obj.name))

        def _launch(local_path: str, remote_path: str, name: str):
            self._set_loading(False)
            gfile = Gio.File.new_for_path(local_path)
            try:
                # Sniff type for better fallback
                info = gfile.query_info("standard::content-type,standard::type", 0, None)
                
                # If it's a regular file but has no specific extension, launch_default might open Nautilus
                handler = gfile.query_default_handler(None)
                
                if handler and handler.get_id() == "org.gnome.Nautilus.desktop" and info.get_file_type() == Gio.FileType.REGULAR:
                    text_handler = Gio.AppInfo.get_default_for_type("text/plain", False)
                    if text_handler:
                        text_handler.launch([gfile], None)
                        self._start_monitoring(local_path, remote_path, name)
                        self._status_label.set_label(_("Opened {name} with {app}").format(name=name, app=text_handler.get_display_name()))
                        return

                Gio.AppInfo.launch_default_for_uri(gfile.get_uri(), None)
                self._start_monitoring(local_path, remote_path, name)
                self._status_label.set_label(_("Opening {name}...").format(name=name))
            except Exception as e:
                logger.error(f"Launch failed: {e}")
                self._status_label.set_label(_("Failed to open: {e}").format(e=e))

        self._ssh_service.engine.run_coroutine(_mount_and_open())

    def _open_with_selected(self) -> None:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION: return
        file_obj = self._file_store.get_item(pos)
        if not file_obj or file_obj.is_dir: return

        from services.rclone_service import RcloneService
        rclone = RcloneService.get()
        
        self._set_loading(True)
        self._status_label.set_label(_("Ensuring mount for Open With..."))
        
        async def _mount_and_pick():
            mount_uri, error = await rclone.mount(self._connection, self._auth_info)
            
            remote_path = os.path.join(self._current_path, file_obj.name)
            import uuid
            session_id = str(uuid.uuid4())[:8]
            edit_session_dir = os.path.join(self._temp_dir, session_id)
            os.makedirs(edit_session_dir, exist_ok=True)
            local_path = os.path.join(edit_session_dir, file_obj.name)

            if not mount_uri:
                logger.warning(f"Open With: Mount failed ({error}), falling back to direct download.")
                try:
                    await self._sftp.get(remote_path, local_path)
                    GLib.idle_add(lambda: _choose(local_path, remote_path, file_obj.name))
                except Exception as e:
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Fallback failed: {e}").format(e=e))))
                return
            
            mount_path = rclone.get_mount_path(self._connection.id)
            mounted_file = os.path.join(mount_path, self._current_path.lstrip("/"), file_obj.name)
            
            import asyncio
            import shutil
            for _ in range(25):
                if os.path.exists(mounted_file): break
                await asyncio.sleep(0.2)
            
            if not os.path.exists(mounted_file):
                logger.warning(f"File {file_obj.name} missing in mount, downloading directly.")
                try:
                    await self._sftp.get(remote_path, local_path)
                    GLib.idle_add(lambda: _choose(local_path, remote_path, file_obj.name))
                except Exception as e:
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Download failed: {e}").format(e=e))))
                return

            try:
                await asyncio.to_thread(shutil.copy2, mounted_file, local_path)
                GLib.idle_add(lambda: _choose(local_path, remote_path, file_obj.name))
            except Exception as e:
                logger.error(f"Copy from mount failed: {e}, trying direct download.")
                try:
                    await self._sftp.get(remote_path, local_path)
                    GLib.idle_add(lambda: _choose(local_path, remote_path, file_obj.name))
                except Exception as ef:
                    GLib.idle_add(lambda: (self._set_loading(False), self._status_label.set_label(_("Download failed: {e}").format(e=ef))))

        def _choose(local_path: str, remote_path: str, name: str):
            self._set_loading(False)
            gfile = Gio.File.new_for_path(local_path)
            
            try:
                info = gfile.query_info("standard::content-type", 0, None)
                mime = info.get_content_type()
            except:
                mime = "application/octet-stream"

            # Use Gtk.AppChooserDialog to let user pick app
            dialog = Gtk.AppChooserDialog.new_for_content_type(
                self.get_root(),
                Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
                mime
            )
            
            def _on_response(d, response):
                if response == Gtk.ResponseType.OK:
                    appinfo = d.get_app_info()
                    if appinfo:
                        try:
                            appinfo.launch([gfile], None)
                            self._start_monitoring(local_path, remote_path, name)
                            self._status_label.set_label(_("Opened {name} with {app}").format(name=name, app=appinfo.get_display_name()))
                        except Exception as e:
                            self._status_label.set_label(_("Launch failed: {e}").format(e=e))
                d.destroy()
            
            dialog.connect("response", _on_response)
            dialog.present()

        self._ssh_service.engine.run_coroutine(_mount_and_pick())

    def _start_monitoring(self, local_path: str, remote_path: str, name: str) -> None:
        if local_path in self._monitors: return
        
        gfile = Gio.File.new_for_path(local_path)
        try:
            # Record initial state
            if os.path.exists(local_path):
                self._initial_states[local_path] = (os.path.getmtime(local_path), os.path.getsize(local_path))
            
            monitor = gfile.monitor_file(Gio.FileMonitorFlags.NONE, None)
            monitor.connect("changed", self._on_file_monitor_event, local_path, remote_path, name)
            self._monitors[local_path] = monitor
            self._active_edits[remote_path] = local_path
            logger.info(f"Started monitoring {local_path} for edits")
            
            # Start the background occupancy check loop
            self._ssh_service.engine.run_coroutine(self._bg_occupancy_loop(local_path, remote_path, name))
        except Exception as e:
            logger.error(f"Failed to start file monitor: {e}")

    def _stop_monitoring(self, local_path: str) -> None:
        monitor = self._monitors.pop(local_path, None)
        if monitor:
            monitor.cancel()
        
        # Cleanup mapping
        for r_path, l_path in list(self._active_edits.items()):
            if l_path == local_path:
                self._active_edits.pop(r_path, None)
                break

        self._initial_states.pop(local_path, None)
        self._pending_prompts.discard(local_path)
        
        # Cleanup temp file and its parent session dir
        if os.path.exists(local_path) and local_path.startswith(self._temp_dir):
            try:
                os.remove(local_path)
                # Try to remove the session sub-dir
                parent = os.path.dirname(local_path)
                if parent != self._temp_dir:
                    import shutil
                    shutil.rmtree(parent)
            except: pass
            
        logger.info(f"Stopped monitoring and cleaned up session for {local_path}")

    def _on_file_monitor_event(self, monitor: Gio.FileMonitor, file: Gio.File, other_file: Gio.File, 
                             event: Gio.FileMonitorEvent, local_path: str, remote_path: str, name: str) -> None:
        if event in (Gio.FileMonitorEvent.CHANGES_DONE_HINT, Gio.FileMonitorEvent.CHANGED):
            # If not already monitoring via loop, restart loop (though loop is usually enough)
            if local_path in self._monitors and local_path not in self._pending_prompts:
                # We don't necessarily need to do anything here if the loop is already running
                pass

    async def _bg_occupancy_loop(self, local_path: str, remote_path: str, name: str):
        """Asynchronous background loop to check for occupancy and changes."""
        import psutil
        import asyncio
        
        while self._sftp and local_path in self._monitors:
            if local_path in self._pending_prompts:
                await asyncio.sleep(2)
                continue
                
            is_occupied = False
            try:
                # Heavy check off-main-thread
                for proc in psutil.process_iter(['open_files', 'cmdline']):
                    try:
                        info_files = proc.info.get('open_files')
                        if info_files:
                            for f in info_files:
                                if f.path == local_path:
                                    is_occupied = True
                                    break
                        if is_occupied: break
                        
                        cmdline = proc.info.get('cmdline')
                        if cmdline:
                            for arg in cmdline:
                                if local_path in arg:
                                    is_occupied = True
                                    break
                        if is_occupied: break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logger.debug(f"Occupancy check error: {e}")

            if is_occupied:
                await asyncio.sleep(2)
                continue

            # Occupancy released! Check for changes
            changed = False
            try:
                if os.path.exists(local_path):
                    curr_mtime = os.path.getmtime(local_path)
                    curr_size = os.path.getsize(local_path)
                    init_mtime, init_size = self._initial_states.get(local_path, (0, 0))
                    if curr_mtime > init_mtime or curr_size != init_size:
                        changed = True
            except Exception as e:
                logger.error(f"Failed to check for changes background: {e}")

            if not changed:
                logger.info(f"No changes detected for {name}, stopping monitoring background.")
                from services.async_engine import call_ui_sync
                call_ui_sync(self._stop_monitoring, local_path)
                break
                
            # Changed! Notify UI
            logger.info(f"Changes detected for {name}, prompting for sync via UI thread.")
            from services.async_engine import call_ui_sync
            call_ui_sync(self._trigger_sync_prompt, local_path, remote_path, name)
            # Once prompted, we stop this loop. The prompt callback will handle stopping monitor.
            break

            await asyncio.sleep(2)

    def _trigger_sync_prompt(self, local_path: str, remote_path: str, name: str) -> None:
        if not self._sftp or local_path in self._pending_prompts:
            return

        self._pending_prompts.add(local_path)
        
        from views.dialogs import prompt_confirmation
        def _on_response(yes: bool):
            logger.info(f"User response for sync {name}: {yes}")
            self._pending_prompts.discard(local_path)
            if yes:
                # Sync first, then stop monitoring (which deletes the file)
                self._force_sync_specific(local_path, remote_path, name, 
                                        callback=lambda: self._stop_monitoring(local_path))
            else:
                self._stop_monitoring(local_path)
                
        if self._auto_sync:
            _on_response(True)
        else:
            prompt_confirmation(
                self.get_root(),
                _("File Updated Locally"),
                _("The file '{name}' has been modified and saved.\nUpdate the remote copy on the server?").format(name=name),
                _("Update Remote"),
                False,
                _on_response
            )

    def _force_sync_selected(self) -> None:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION: return
        file_obj = self._file_store.get_item(pos)
        if not file_obj or file_obj.is_dir: return

        remote_path = os.path.join(self._current_path, file_obj.name)
        
        # Check if we have an active edit temp file
        local_path = self._active_edits.get(remote_path)
        if not local_path:
            # Fallback to mount (though it's read-only, maybe user changed permissions or something?)
            mount_path = RcloneService.get().get_mount_path(self._connection.id)
            local_path = os.path.join(mount_path, self._current_path.lstrip("/"), file_obj.name)
        
        self._force_sync_specific(local_path, remote_path, file_obj.name)

    def _force_sync_specific(self, local_path: str, remote_path: str, name: str, 
                             callback: Callable[[], None] | None = None) -> None:
        logger.info(f"Starting force sync: {local_path} -> {remote_path}")
        self._set_loading(True)
        self._status_label.set_label(_("Synchronizing {name}...").format(name=name))
        
        async def _bg_sync():
            try:
                await self._sftp.put(local_path, remote_path)
                def _done():
                    self._on_transfer_finish(True, _("Synchronized {name}").format(name=name))
                    if callback: callback()
                GLib.idle_add(_done)
            except Exception as e:
                logger.error(f"Sync failed: {e}")
                GLib.idle_add(self._on_transfer_finish, False, _("Sync error: {e}").format(e=e))
                
        self._ssh_service.engine.run_coroutine(_bg_sync())

    def _delete_selected(self) -> bool:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return False
        file_obj = self._file_store.get_item(pos)
        if not file_obj:
            return False

        from views.dialogs import prompt_confirmation
        def _on_confirm(confirmed: bool):
            if not confirmed:
                return
            
            path = os.path.join(self._current_path, file_obj.name)
            self._set_loading(True)
            self._status_label.set_label(_("Deleting {name}...").format(name=file_obj.name))
            
            async def _bg_delete():
                try:
                    if file_obj.is_dir:
                        # asyncssh sftp doesn't have recursive rmdir, need to handle or assume empty?
                        # Actually asyncssh has sftp.rmdir but for non-empty we might need more.
                        # For simple UX, let's try rmdir first.
                        await self._sftp.rmdir(path)
                    else:
                        await self._sftp.remove(path)
                    GLib.idle_add(self._on_transfer_finish, True, _("Deleted {name}").format(name=file_obj.name))
                except Exception as e:
                    logger.error(f"Delete failed: {e}")
                    GLib.idle_add(self._on_transfer_finish, False, _("Delete failed: {e}").format(e=e))
            
            self._bg_task = self._ssh_service.engine.run_coroutine(_bg_delete())

        prompt_confirmation(
            self.get_root(),
            _("Delete Item"),
            _("Are you sure you want to delete '{name}'?\nThis action cannot be undone.").format(name=file_obj.name),
            _("Delete"),
            True,
            _on_confirm
        )
        return True

    def _download_selected(self) -> None:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return
        file_obj = self._file_store.get_item(pos)
        if not file_obj:
            return

        dialog = Gtk.FileDialog.new()
        if file_obj.is_dir:
            dialog.set_title(_("Download Directory: {name}").format(name=file_obj.name))
            dialog.select_folder(self.get_root(), None, self._on_download_folder_cb, file_obj)
        else:
            dialog.set_title(_("Download File: {name}").format(name=file_obj.name))
            dialog.set_initial_name(file_obj.name)
            dialog.save(self.get_root(), None, self._on_download_file_cb, file_obj)

    def _on_download_file_cb(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult, file_obj: SftpFile) -> None:
        try:
            gfile = dialog.save_finish(result)
            if gfile:
                self._run_download_task(file_obj, gfile.get_path())
        except Exception as e:
            logger.info(f"Download cancelled or failed: {e}")

    def _on_download_folder_cb(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult, file_obj: SftpFile) -> None:
        try:
            gfile = dialog.select_folder_finish(result)
            if gfile:
                self._run_download_task(file_obj, gfile.get_path())
        except Exception as e:
            logger.info(f"Download folder cancelled or failed: {e}")

    def _run_download_task(self, file_obj: SftpFile, target_path: str) -> None:
        import os, asyncssh
        src_path = os.path.join(self._current_path, file_obj.name)
        self._set_loading(True)
        self._status_label.set_label(_("Downloading {name}...").format(name=file_obj.name))
        
        async def _bg_download():
            try:
                await asyncssh.scp((self._ssh_conn, src_path), target_path, preserve=True, recurse=True)
                GLib.idle_add(self._on_transfer_finish, True, _("Downloaded {name} to local system").format(name=file_obj.name))
            except Exception as e:
                GLib.idle_add(self._on_transfer_finish, False, str(e))
        self._bg_task = self._ssh_service.engine.run_coroutine(_bg_download())

    def _paste_from_clipboard(self) -> bool:
        clipboard = self.get_clipboard()
        clipboard.read_text_async(None, self._on_clipboard_read)
        return True

    def _on_clipboard_read(self, clipboard: Gdk.Clipboard, result: Gio.AsyncResult) -> None:
        try:
            text = clipboard.read_text_finish(result)
            if text:
                self._handle_paste_text(text)
        except Exception as e:
            logger.error(f"Failed to read clipboard: {e}")

    def _handle_paste_text(self, text: str) -> None:
        text = text.strip()
        import urllib.parse
        import asyncssh
        dst_path = self._current_path

        if text.startswith("sentinel-sftp://"):
            parsed = urllib.parse.urlparse(text)
            src_conn_id = parsed.netloc
            src_path = parsed.path
            
            if src_conn_id != self._connection.id:
                # Cross-server transfer via rclone
                from services.rclone_service import RcloneService
                from views.main_window import SentinelWindow
                
                # 1. Try to find active auth from open tabs across ALL windows
                src_data = None
                app = Gtk.Application.get_default()
                if app:
                    for window in app.get_windows():
                        # We use the title or a check to ensure it's a SentinelWindow
                        if hasattr(window, "_terminal_tab_view"):
                             src_data = window._terminal_tab_view.find_sftp_tab_data(src_conn_id)
                             if src_data:
                                 break
                
                if not src_data:
                    # Fallback: Load connection from DB to at least show the hostname
                    from db.database import Database
                    db = Database()
                    db.open()
                    src_conn = db.get_connection(src_conn_id)
                    db.close()
                    
                    if not src_conn:
                        GLib.idle_add(lambda: self._status_label.set_label(_("Source connection not found in database.")))
                        return

                    # We don't have auth_info. For now, require the tab to be open.
                    # In a future version, we could prompt for auth here.
                    def _err_no_auth():
                        self._status_label.set_label(_("Source SFTP session must be active to perform transfer."))
                        self._set_loading(False)
                    GLib.idle_add(_err_no_auth)
                    return
                
                src_conn, src_auth = src_data
                
                # 2. Execute transfer
                self._set_loading(True)
                self._status_label.set_label(_("Starting cross-server transfer from {hostname}...").format(hostname=src_conn.hostname))
                
                final_dst = os.path.join(dst_path, os.path.basename(src_path))
                if src_path.endswith("/"): final_dst += "/"

                async def _bg_rclone_transfer():
                    rclone = RcloneService.get()
                    
                    def _prog(percent, line):
                        GLib.idle_add(lambda: self._status_label.set_label(_("Transferring: {percent}%").format(percent=int(percent))))

                    success, err = await rclone.transfer(
                        src_conn, src_auth, src_path,
                        self._connection, self._auth_info, final_dst,
                        on_progress=_prog
                    )
                    
                    if success:
                        GLib.idle_add(self._on_transfer_finish, True, _("Cross-server transfer complete"))
                    else:
                        GLib.idle_add(self._on_transfer_finish, False, _("Transfer failed: {err}").format(err=err))
                
                self._bg_task = self._ssh_service.engine.run_coroutine(_bg_rclone_transfer())
                return
            
        elif text.startswith("file://") or text.startswith("/"):
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            local_paths = []
            for line in lines:
                if line.startswith("file://"):
                    local_paths.append(urllib.parse.unquote(line[7:]))
                elif line.startswith("/"):
                    local_paths.append(line)
            
            if local_paths:
                self._set_loading(True)
                self._status_label.set_label(_("Uploading {count} items...").format(count=len(local_paths)))
                
                async def _bg_upload():
                    try:
                        await asyncssh.scp(local_paths, (self._ssh_conn, dst_path), preserve=True, recurse=True)
                        GLib.idle_add(self._on_transfer_finish, True, _("Uploaded successfully"))
                    except Exception as e:
                        GLib.idle_add(self._on_transfer_finish, False, str(e))
                self._bg_task = self._ssh_service.engine.run_coroutine(_bg_upload())

    def _on_transfer_finish(self, success: bool, msg: str) -> None:
        self._set_loading(False)
        self._status_label.set_label(msg)
        if success:
            self._load_path(self._current_path)

    def _refresh_store(self) -> None:
        """Repopulate the ListStore from cached all_items applying hidden filter."""
        self._file_store.remove_all()
        count = 0
        for f in self._all_items:
            if not self._show_hidden and f.name.startswith("."):
                continue
            self._file_store.append(f)
            count += 1
        self._status_label.set_label(_("{count} items in {path}").format(count=count, path=self._current_path))

    def _on_toggle_show_hidden(self, _action: Gio.SimpleAction, _param: GLib.Variant | None) -> None:
        self._show_hidden = not self._show_hidden
        self._refresh_store()
        # Update action state
        _action.set_state(GLib.Variant.new_boolean(self._show_hidden))
        # No need to call _load_path, _refresh_store handles the display update from cached items

    def _on_toggle_auto_sync(self, action: Gio.SimpleAction, value: GLib.Variant | None) -> None:
        self._auto_sync = not self._auto_sync
        action.set_state(GLib.Variant.new_boolean(self._auto_sync))
        if self._auto_sync:
            self._status_label.set_label(_("Auto-sync enabled for this session."))
        else:
            self._status_label.set_label(_("Auto-sync disabled."))

    def terminate(self) -> None:
        # Use list() to avoid "dictionary changed size during iteration"
        for monitor in monitors:
            monitor.cancel()
        self.terminate_auth()
        self._monitors.clear()
        self._initial_states.clear()
        self._pending_prompts.clear()
        
        # Cleanup temp dir
        if os.path.exists(self._temp_dir):
            import shutil
            try: shutil.rmtree(self._temp_dir)
            except: pass
        
        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()
            
        if self._ssh_conn:
            async def _close():
                try:
                    from services.rclone_service import RcloneService
                    await RcloneService.get().unmount(self._connection.id)
                    self._ssh_conn.close()
                except: pass
            self._ssh_service.engine.run_coroutine(_close())
            self._ssh_conn = None
            self._sftp = None
    
    def terminate_auth(self) -> None:
        """Clear sensitive credentials from memory."""
        if hasattr(self, "_auth_info"):
            for key in list(self._auth_info.keys()):
                val = self._auth_info.pop(key)
                if isinstance(val, SecureBytes):
                    val.clear()
                # If it's a raw string, we can't wipe it but we've removed the reference

    def _on_calculate_size(self) -> bool:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return False
        file_obj = self._file_store.get_item(pos)
        if not file_obj or not file_obj.props.is_dir:
            return False

        path = os.path.join(self._current_path, file_obj.props.name)
        self._status_label.set_label(_("Calculating size for {name}...").format(name=file_obj.props.name))
        
        async def _run_calc():
            try:
                # Use du -sh for efficient calculation on server
                res = await self._ssh_conn.run(f'du -sh "{path}"', check=True)
                if res.stdout:
                    # Output: "1.2G\t/root/foo"
                    size_val = res.stdout.split()[0]
                    def _update_ui():
                        from views.dialogs import show_info
                        show_info(self.get_root(), _("Size of {name}").format(name=file_obj.props.name), _("The directory occupies: {size}").format(size=size_val))
                        self._status_label.set_label(_("Size of {name}: {size}").format(name=file_obj.props.name, size=size_val))
                    GLib.idle_add(_update_ui)
            except Exception as e:
                msg = str(e)
                GLib.idle_add(lambda: self._status_label.set_label(_("Size calculation failed: {msg}").format(msg=msg)))
        
        self._ssh_service.engine.run_coroutine(_run_calc())
        return True

    def _on_properties_selected(self) -> bool:
        pos = self._selection_model.get_selected()
        if pos == Gtk.INVALID_LIST_POSITION:
            return False
        file_obj = self._file_store.get_item(pos)
        if not file_obj:
            return False

        from views.dialogs import show_file_properties
        file_info = {
            "name": file_obj.props.name,
            "is_dir": file_obj.props.is_dir,
            "size_str": file_obj.size_str,
            "mtime_str": file_obj.mtime_str,
            "permissions_oct": oct(file_obj.props.permissions)[-3:] if file_obj.props.permissions else "Unknown",
            "uid": file_obj.props.uid,
            "gid": file_obj.props.gid,
            "path": os.path.join(self._current_path, file_obj.props.name)
        }
        show_file_properties(self.get_root(), file_info)
        return True

    @property
    def title(self) -> str:
        return _("SFTP: {hostname}").format(hostname=self._connection.hostname)
