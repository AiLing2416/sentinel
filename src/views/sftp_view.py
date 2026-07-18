# SPDX-License-Identifier: GPL-3.0-or-later

"""SFTP file-browser view — rewrote from scratch for Sentinel v0.3."""

from __future__ import annotations

import gettext
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, Sequence

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
gi.require_version("GdkWayland", "4.0")
gi.require_version("GdkX11", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango, GdkWayland, GdkX11

from models.connection import Connection
from services.async_engine import call_ui_sync
from services.rclone_service import RcloneService
from services.sftp_service import SftpService
from services.ssh_service import SSHService
from db.database import Database

_ = gettext.gettext
logger = logging.getLogger(__name__)

MAX_DIRECT_EDIT_BYTES = 200 * 1024 * 1024   # 200 MB soft limit


# ---------------------------------------------------------------------------
# GObject model for the ColumnView
# ---------------------------------------------------------------------------

class SftpFile(GObject.Object):
    """GObject wrapper around a remote file entry for use with Gtk.ColumnView."""

    name        = GObject.Property(type=str,  default="")
    # File sizes and timestamps can exceed 2^31 on 64-bit systems.
    # GObject's plain `type=int` maps to gint (32-bit), so we must use
    # TYPE_INT64 to avoid a 'could not convert from int to gint' TypeError.
    size        = GObject.Property(type=GObject.TYPE_INT64, default=0)
    mtime       = GObject.Property(type=GObject.TYPE_INT64, default=0)
    is_dir      = GObject.Property(type=bool, default=False)
    permissions = GObject.Property(type=int,  default=0)
    uid         = GObject.Property(type=int,  default=0)
    gid         = GObject.Property(type=int,  default=0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    @property
    def icon_name(self) -> str:
        if self.is_dir:
            return "folder-symbolic"
        # Guess icon based on name
        content_type, _ = Gio.content_type_guess(self.name, None)
        if content_type:
            icon = Gio.content_type_get_icon(content_type)
            if icon:
                # Return the first name from the themed icon
                names = icon.get_names()
                if names: return names[0]
        return "text-x-generic-symbolic"

    @property
    def size_str(self) -> str:
        if self.is_dir:
            return "—"
        s = float(self.size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if s < 1024:
                return f"{int(s)} {unit}" if unit == "B" else f"{s:.1f} {unit}"
            s /= 1024
        return f"{s:.1f} PB"

    @property
    def mtime_str(self) -> str:
        try:
            return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return "—"


# ---------------------------------------------------------------------------
# Edit-session bookkeeping
# ---------------------------------------------------------------------------

@dataclass
class EditSession:
    """Tracks one externally-opened file for auto-sync."""
    local_path:  str
    remote_path: str
    filename:    str
    mtime:       float
    monitor:     Gio.FileMonitor
    directory:   str                    # The directory being monitored
    pending:     bool = False           # True while a sync-confirm dialog is open
    timer_id:    int = 0                # GSourse ID for debouncing


# ---------------------------------------------------------------------------
# Main widget
# ---------------------------------------------------------------------------

class SftpTab(Gtk.Box):
    """Full SFTP file-browser widget embedded in a tab page."""

    def __init__(
        self,
        connection: Connection,
        ssh_service: SSHService,
        on_close: Optional[Callable] = None,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self._conn       = connection
        self._ssh        = ssh_service
        self._backend    = SftpService(connection, ssh_service)
        self._rclone     = RcloneService.get()
        self._on_close   = on_close
        self._is_flatpak = os.path.exists("/.flatpak-info")

        self._current_path = "."
        self._history:       list[str] = []
        self._history_idx:   int       = -1
        self._all_items:     list[SftpFile] = []
        self._edit_sessions: dict[str, EditSession] = {}   # keyed by local_path
        self._show_hidden  = False
        self._auto_sync    = True # Default to True for better UX

        self._store = Gio.ListStore.new(SftpFile)
        self._build_ui()
        
        # Drag-and-drop state
        self._dnd_downloads: set[str] = set() # remote_paths currently being downloaded
        self._run_async(self._do_connect())

    @property
    def title(self) -> str:
        """Tab title shown by TerminalTabView."""
        user = self._conn.username
        host = self._conn.hostname
        return f"SFTP — {user}@{host}" if user else f"SFTP — {host}"

    @property
    def connection(self) -> Connection:
        """Expose connection so TerminalTabView can track this tab."""
        return self._conn

    # ── Public lifecycle ────────────────────────────────────────────

    def terminate(self) -> None:
        """Clean up monitors, temp files, FUSE mount and SSH connection."""
        logger.info("SftpTab[%s]: terminating", self._conn.hostname)
        for es in list(self._edit_sessions.values()):
            es.monitor.cancel()
            if es.timer_id:
                GLib.source_remove(es.timer_id)
        self._edit_sessions.clear()
        # self._run_async(self._rclone.unmount(self._conn.id))
        self._run_async(self._backend.disconnect())

    # ── UI construction ─────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Toolbar ──
        tb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        tb.add_css_class("toolbar")
        tb.set_margin_top(4)
        tb.set_margin_bottom(4)

        self._back_btn = Gtk.Button(icon_name="go-previous-symbolic", sensitive=False)
        self._back_btn.connect("clicked", lambda _: self._navigate(-1))
        tb.append(self._back_btn)

        self._fwd_btn = Gtk.Button(icon_name="go-next-symbolic", sensitive=False)
        self._fwd_btn.connect("clicked", lambda _: self._navigate(1))
        tb.append(self._fwd_btn)

        up_btn = Gtk.Button(icon_name="go-up-symbolic")
        up_btn.set_tooltip_text(_("Parent directory"))
        up_btn.connect("clicked", lambda _: self._load_path(
            os.path.dirname(self._current_path)
        ))
        tb.append(up_btn)

        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
        refresh_btn.set_tooltip_text(_("Refresh"))
        refresh_btn.connect("clicked", lambda _: self._load_path(self._current_path))
        tb.append(refresh_btn)

        # New file / New folder split button
        new_menu_btn = Gtk.MenuButton(icon_name="list-add-symbolic")
        new_menu_btn.set_tooltip_text(_("New…"))
        new_m = Gio.Menu()
        new_m.append(_("New File"),   "sftp.new-file")
        new_m.append(_("New Folder"), "sftp.new-folder")
        new_menu_btn.set_menu_model(new_m)
        tb.append(new_menu_btn)

        self._path_entry = Gtk.Entry(hexpand=True)
        self._path_entry.set_placeholder_text(_("Remote path"))
        self._path_entry.connect("activate", lambda e: self._load_path(e.get_text()))
        tb.append(self._path_entry)

        # View options
        view_btn = Gtk.MenuButton(icon_name="view-more-symbolic")
        view_m = Gio.Menu()
        view_m.append(_("Show Hidden Files"), "sftp.show-hidden")
        view_m.append(_("Auto-sync on Save"),  "sftp.auto-sync")
        view_btn.set_menu_model(view_m)
        tb.append(view_btn)

        self.append(tb)

        # ── File list ──
        self._cv = Gtk.ColumnView(hexpand=True, vexpand=True)
        self._cv.add_css_class("sftp-file-list")

        # SortListModel wraps the raw store; SingleSelection sits on top of it
        self._sort_model = Gtk.SortListModel.new(self._store, self._cv.get_sorter())
        self._sel        = Gtk.SingleSelection(model=self._sort_model)
        self._cv.set_model(self._sel)
        self._cv.connect("activate", self._on_row_activate)

        self._cv.append_column(self._make_column(
            _("Name"), self._setup_name_cell, self._bind_name_cell,
            expand=True, resizable=True,
            sorter=Gtk.CustomSorter.new(self._sort_by_name),
        ))
        self._cv.append_column(self._make_column(
            _("Size"), self._setup_text_cell, self._bind_size_cell,
            fixed_width=100,
        ))
        self._cv.append_column(self._make_column(
            _("Modified"), self._setup_text_cell, self._bind_mtime_cell,
            fixed_width=160,
        ))

        self.append(Gtk.ScrolledWindow(vexpand=True, child=self._cv))

        # Right-click context menu
        self._pop = Gtk.PopoverMenu.new_from_model(self._build_context_menu())
        self._pop.set_parent(self._cv)
        self._pop.set_has_arrow(False)
        gc = Gtk.GestureClick(button=Gdk.BUTTON_SECONDARY)
        gc.connect("pressed", self._on_right_click)
        self._cv.add_controller(gc)

        # Drag-and-drop upload / Remote-to-Remote
        # In GTK4, to support multiple formats (GType and custom MIME), we must
        # pass them via Gdk.ContentFormats to the DropTarget constructor.
        formats = Gdk.ContentFormats.new([
            "application/x-sentinel-sftp-source"
        ])
        formats = formats.union(Gdk.ContentFormats.new_for_gtype(Gdk.FileList))
        
        drop = Gtk.DropTarget(formats=formats, actions=Gdk.DragAction.COPY)
        drop.connect("drop", self._on_dnd_drop)
        self._cv.add_controller(drop)

        # ── Actions ──
        self._ag = Gio.SimpleActionGroup.new()
        self._register_actions()
        self.insert_action_group("sftp", self._ag)

        # ── Status bar ──
        sb = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        sb.add_css_class("toolbar")

        self._spinner = Gtk.Spinner()
        self._indicator = Gtk.Stack()
        self._indicator.add_named(self._spinner, "spin")
        check = Gtk.Image.new_from_icon_name("object-select-symbolic")
        check.add_css_class("success")
        self._indicator.add_named(check, "ok")
        sb.append(self._indicator)

        self._status_lbl = Gtk.Label(label=_("Connecting…"), xalign=0, hexpand=True)
        self._status_lbl.add_css_class("dim-label")
        self._status_lbl.add_css_class("caption")
        sb.append(self._status_lbl)

        self.append(sb)

    def _build_context_menu(self) -> Gio.Menu:
        m = Gio.Menu()
        m.append(_("Open"),         "sftp.open")
        m.append(_("Open With…"),   "sftp.open-with")
        edit_sec = Gio.Menu()
        edit_sec.append(_("Rename"), "sftp.rename")
        edit_sec.append(_("Remove"), "sftp.remove")
        m.append_section(None, edit_sec)
        xfer_sec = Gio.Menu()
        xfer_sec.append(_("Upload Changes"), "sftp.sync-back")
        xfer_sec.append(_("Download…"), "sftp.download")
        m.append_section(None, xfer_sec)
        return m

    def _register_actions(self) -> None:
        simple = [
            ("open",       lambda *_: self._open_selected(use_chooser=False)),
            ("open-with",  lambda *_: self._open_selected(use_chooser=True)),
            ("rename",     lambda *_: self._rename_selected()),
            ("remove",     lambda *_: self._remove_selected()),
            ("download",   lambda *_: self._download_selected()),
            ("sync-back",  lambda *_: self._sync_selected()),
            ("new-file",   lambda *_: self._new_entry(is_folder=False)),
            ("new-folder", lambda *_: self._new_entry(is_folder=True)),
        ]
        for name, cb in simple:
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", cb)
            self._ag.add_action(act)

        # Stateful toggles
        for name, attr in (("show-hidden", "_show_hidden"), ("auto-sync", "_auto_sync")):
            act = Gio.SimpleAction.new_stateful(
                name, None, GLib.Variant.new_boolean(getattr(self, attr))
            )
            act.connect("activate", self._toggle_action, attr)
            self._ag.add_action(act)

    @staticmethod
    def _make_column(
        title: str,
        setup_cb: Callable,
        bind_cb:  Callable,
        *,
        expand:      bool = False,
        resizable:   bool = False,
        fixed_width: int  = -1,
        sorter:      Gtk.Sorter | None = None,
    ) -> Gtk.ColumnViewColumn:
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", setup_cb)
        factory.connect("bind",  bind_cb)
        col = Gtk.ColumnViewColumn(title=title, factory=factory)
        col.set_expand(expand)
        col.set_resizable(resizable)
        if fixed_width > 0:
            col.set_fixed_width(fixed_width)
        if sorter:
            col.set_sorter(sorter)
        return col

    # ── Cell setup / bind ───────────────────────────────────────────

    def _setup_name_cell(self, _f, li: Gtk.ListItem) -> None:
        box = Gtk.Box(spacing=8)
        box.append(Gtk.Image())
        label = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        label.set_hexpand(True)
        box.append(label)
        li.set_child(box)

        # ── Setup Drag Source (Once per widget) ──
        ds = Gtk.DragSource.new()
        ds.set_actions(Gdk.DragAction.COPY)
        # item will be retrieved at drag time via li.get_item()
        ds.connect("prepare", lambda *args: self._on_drag_prepare_li(li, *args))
        ds.connect("drag-begin", self._on_drag_begin)
        box.add_controller(ds)

    def _on_drag_prepare_li(self, li: Gtk.ListItem, _ds, _x, _y) -> Gdk.ContentProvider:
        item = li.get_item()
        if not item: return None
        return self._on_drag_prepare(_ds, _x, _y, item)

    def _bind_name_cell(self, _f, li: Gtk.ListItem) -> None:
        item: SftpFile = li.get_item()
        box = li.get_child()
        if not (item and box): return
        
        # Explicit child lookup for robustness
        img = box.get_first_child()
        lbl = img.get_next_sibling() if img else None
        
        if img:
            img.set_from_icon_name(item.icon_name)
        if lbl:
            lbl.set_text(item.name)

    # Removed redundant DragSource setup from bind phase

    def _on_drag_prepare(self, _ds: Gtk.DragSource, _x: float, _y: float, item: SftpFile) -> Gdk.ContentProvider:
        remote_path = os.path.join(self._current_path, item.name)
        
        # 1. Custom MIME for Remote-to-Remote (internal relay)
        meta = {
            "conn_id": self._conn.id,
            "remote_path": remote_path,
            "filename": item.name,
            "is_dir": item.is_dir,
            "size": item.size,
        }
        bytes_data = GLib.Bytes.new(json.dumps(meta).encode("utf-8"))
        cp_sentinel = Gdk.ContentProvider.new_for_bytes("application/x-sentinel-sftp-source", bytes_data)
        
        # 2. Support for external file managers (Local-to-Remote)
        # To avoid 0-byte files, we download to .tmp and rename upon completion.
        dnd_cache = os.path.join(GLib.get_user_cache_dir(), "sentinel", "dnd")
        os.makedirs(dnd_cache, exist_ok=True)
        
        local_final = os.path.join(dnd_cache, item.name)
        # Use a hidden .tmp name with timestamp
        import time
        tmp_name = f".{int(time.time())}-{item.name}.tmp"
        local_tmp = os.path.join(dnd_cache, tmp_name)
        
        if not item.is_dir:
            # Check if we are already downloading this
            if remote_path not in self._dnd_downloads:
                # User requested ALWAYS re-download
                self._run_async(self._do_dnd_download(remote_path, local_tmp, local_final))

        # We return the FINAL path. Nautilus will wait/retry if it doesn't exist 
        # or show error, but won't get a 0-byte file while it's in .tmp state.
        gfile = Gio.File.new_for_path(local_final)
        fl = Gdk.FileList.new_from_list([gfile])
        cp_files = Gdk.ContentProvider.new_for_value(fl)
        
        return Gdk.ContentProvider.new_union([cp_sentinel, cp_files])

    async def _do_dnd_download(self, remote_path: str, tmp_path: str, final_path: str) -> None:
        self._dnd_downloads.add(remote_path)
        filename = os.path.basename(final_path)
        
        # Set UI to downloading state
        GLib.idle_add(lambda: self._update_dnd_ui(True, filename))
        
        try:
            # Download to .tmp
            await self._backend.download(remote_path, tmp_path)
            
            # Atomic rename if final doesn't exist
            if not os.path.exists(final_path):
                os.rename(tmp_path, final_path)
            else:
                # If it appeared in between, just remove tmp
                os.remove(tmp_path)
                
            logger.info("DND Download complete: %s", final_path)
        except Exception as exc:
            logger.error("DND Download failed: %s", exc)
            try: os.remove(tmp_path)
            except OSError: pass
        finally:
            self._dnd_downloads.discard(remote_path)
            GLib.idle_add(lambda: self._update_dnd_ui(False))

    def _update_dnd_ui(self, active: bool, filename: str = "") -> None:
        """Update tab icon and status label for DND activity."""
        # Find the tab page to change icon
        page = None
        parent = self.get_parent()
        while parent:
            if parent.__class__.__name__ == "TabView": # Adw.TabView
                # Find the page containing this widget
                for i in range(parent.get_n_pages()):
                    p = parent.get_nth_page(i)
                    if p.get_child() == self:
                        page = p
                        break
                break
            parent = parent.get_parent()

        if active:
            self._status_lbl.set_label(_("Downloading for drag: {f}…").format(f=filename))
            if page:
                page.set_icon(Gio.ThemedIcon.new("folder-download-symbolic"))
        else:
            self._status_lbl.set_label(_("{n} items").format(n=self._store.get_n_items()))
            if page:
                page.set_icon(Gio.ThemedIcon.new("folder-symbolic"))

    def _on_drag_begin(self, ds: Gtk.DragSource, drag: Gdk.Drag) -> None:
        # ds.get_widget() is the ListItem's child (the Box)
        # But we added the controller to the ListItem itself, so ds.get_widget()
        # might be the Box we created.
        box = ds.get_widget()
        if box:
            # icon from the first child (Image)
            img = box.get_first_child()
            if img:
                ds.set_icon(img.get_paintable(), 0, 0)

    @staticmethod
    def _setup_text_cell(_f, li: Gtk.ListItem) -> None:
        li.set_child(Gtk.Label(xalign=0))

    @staticmethod
    def _bind_size_cell(_f, li: Gtk.ListItem) -> None:
        li.get_child().set_text(li.get_item().size_str)

    @staticmethod
    def _bind_mtime_cell(_f, li: Gtk.ListItem) -> None:
        li.get_child().set_text(li.get_item().mtime_str)

    # ── Sort ────────────────────────────────────────────────────────

    @staticmethod
    def _sort_by_name(a: SftpFile, b: SftpFile, _) -> Gtk.Ordering:
        # Folders first, then alphabetical
        if a.is_dir != b.is_dir:
            return Gtk.Ordering.SMALLER if a.is_dir else Gtk.Ordering.LARGER
        return (
            Gtk.Ordering.SMALLER
            if a.name.lower() < b.name.lower()
            else Gtk.Ordering.LARGER
        )

    # ── Async helper ────────────────────────────────────────────────

    def _run_async(self, coro) -> None:
        self._ssh.engine.run_coroutine(coro)

    # ── Loading state ────────────────────────────────────────────────

    def _set_loading(self, loading: bool, message: str | None = None) -> None:
        if loading:
            self._spinner.start()
            self._indicator.set_visible_child_name("spin")
        else:
            self._spinner.stop()
            self._indicator.set_visible_child_name("ok")
        if message is not None:
            self._status_lbl.set_label(message)

    def _set_status(self, msg: str) -> None:
        self._status_lbl.set_label(msg)

    # ── Connection ──────────────────────────────────────────────────

    async def _do_connect(self) -> None:
        from views.dialogs import (
            prompt_host_key, prompt_password,
            prompt_vault_item_selection, prompt_vault_unlock,
        )

        def _ask_vault_unlock(name: str, resolve: Callable) -> None:
            def _after_pw(pw: str | None) -> None:
                if pw:
                    self._run_async(self._unlock_vault(pw, resolve))
                else:
                    resolve(False)
            prompt_vault_unlock(self.get_root(), name, _after_pw)

        def _ask_password_sftp(conn, resolve):
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
                _("Password"),
                f"{conn.username}@{conn.hostname}",
                _on_resolved,
                show_remember=True
            )

        cbs = {
            "ask_password":    _ask_password_sftp,
            "ask_passphrase":  lambda p, r: prompt_password(self.get_root(), _("Key Passphrase"), p, r),
            "ask_host_key":    lambda h, fp, alg, r: prompt_host_key(self.get_root(), h, fp, alg, r),
            "ask_vault_unlock": _ask_vault_unlock,
            "ask_vault_item":  lambda items, r: prompt_vault_item_selection(self.get_root(), items, r),
            "on_error":        lambda m: GLib.idle_add(lambda: self._set_loading(False, m)),
        }

        call_ui_sync(self._set_loading, True, _("Connecting…"))
        ok = await self._backend.connect(
            cbs,
            status_cb=lambda m: GLib.idle_add(lambda: self._set_status(m)),
        )
        if ok:
            cwd = await self._backend.get_cwd()
            GLib.idle_add(self._on_connected, cwd)
        else:
            GLib.idle_add(lambda: self._set_loading(False, _("Connection failed")))

    async def _unlock_vault(self, pw: str, resolve: Callable) -> None:
        from services.vault_service import VaultService
        ok = await VaultService.get().active_backend.unlock(pw)
        resolve(ok)

    def _on_connected(self, cwd: str) -> None:
        self._load_path(cwd)
        # Disable FUSE mount - we use pure SFTP for better reliability in Flatpak
        # self._run_async(self._ensure_mount())

    async def _ensure_mount(self) -> None:
        path, err = await self._rclone.mount(self._conn, self._backend.auth_info)
        if err:
            logger.warning("RcloneService: background mount failed: %s", err)
        else:
            logger.info("RcloneService: mount ready at %s", path)

    # ── Navigation ──────────────────────────────────────────────────

    def _load_path(self, path: str) -> None:
        self._set_loading(True, _("Loading…"))

        async def _fetch():
            try:
                entries, resolved = await self._backend.list_dir(path)
                GLib.idle_add(self._populate, entries, resolved)
            except Exception as exc:
                logger.error("list_dir failed: %s", exc)
                GLib.idle_add(lambda: self._set_loading(False, str(exc)))

        self._run_async(_fetch())

    def _populate(self, entries: list, resolved: str) -> None:
        self._all_items = [SftpFile(**e) for e in entries]
        self._current_path = resolved
        self._path_entry.set_text(resolved)
        self._push_history(resolved)
        self._refresh_store()
        self._set_loading(False)

    def _refresh_store(self) -> None:
        self._store.remove_all()
        shown = 0
        for f in self._all_items:
            if not self._show_hidden and f.name.startswith("."):
                continue
            self._store.append(f)
            shown += 1
        self._set_status(f"{shown} {_('items')}")

    def _push_history(self, path: str) -> None:
        if self._history_idx >= 0 and self._history[self._history_idx] == path:
            return
        self._history = self._history[: self._history_idx + 1] + [path]
        self._history_idx = len(self._history) - 1
        self._back_btn.set_sensitive(self._history_idx > 0)
        self._fwd_btn.set_sensitive(self._history_idx < len(self._history) - 1)

    def _navigate(self, direction: int) -> None:
        idx = self._history_idx + direction
        if 0 <= idx < len(self._history):
            self._history_idx = idx
            self._load_path(self._history[idx])

    # ── Selection helper ────────────────────────────────────────────

    def _get_selected(self) -> Optional[SftpFile]:
        """Return the currently selected SftpFile, or None.

        IMPORTANT: queries _sort_model (the sorted view), not the raw _store,
        so the position matches the visual row order.
        """
        pos = self._sel.get_selected()
        return self._sort_model.get_item(pos) if pos != Gtk.INVALID_LIST_POSITION else None

    # ── Row activation (double-click / Enter) ──────────────────────

    def _on_row_activate(self, _cv, pos: int) -> None:
        item: SftpFile | None = self._sort_model.get_item(pos)
        if item is None:
            return
        if item.is_dir:
            self._load_path(os.path.join(self._current_path, item.name))
        else:
            self._open_selected(use_chooser=False)

    # ── Right-click ─────────────────────────────────────────────────

    def _on_right_click(self, _g, _n, x: float, y: float) -> None:
        item = self._get_selected()
        has = item is not None
        can_sync = False
        if has and not item.is_dir:
            full_path = os.path.join(self._current_path, item.name)
            # Find if this remote path has an active edit session
            for session in self._edit_sessions.values():
                if session.remote_path == full_path:
                    can_sync = True
                    break

        for name in ("open", "open-with", "rename", "remove", "download", "sync-back"):
            act = self._ag.lookup_action(name)
            if act:
                if name == "sync-back":
                    act.set_enabled(can_sync)
                else:
                    act.set_enabled(has)
        r = Gdk.Rectangle()
        r.x, r.y, r.width, r.height = int(x), int(y), 1, 1
        self._pop.set_pointing_to(r)
        self._pop.popup()

    # ── Open / Edit ─────────────────────────────────────────────────

    async def _do_edit(self, item: SftpFile, use_chooser: bool = False) -> None:
        """Download for edit using EXISTING session and launch app."""
        remote_path = os.path.join(self._current_path, item.name)
        GLib.idle_add(lambda: self._set_loading(True, _("Opening for edit…")))
        
        try:
            # Generate a local path in the edit cache
            # (Note: we use a unique subfolder per file to avoid collisions)
            import hashlib
            h = hashlib.md5(remote_path.encode()).hexdigest()[:16]
            edit_dir = os.path.join(
                GLib.get_user_cache_dir(), "sentinel", "edit", 
                self._conn.id, h
            )
            os.makedirs(edit_dir, exist_ok=True)
            local_path = os.path.join(edit_dir, item.name)
            
            logger.info("SFTP Session reuse: downloading %s for edit", remote_path)
            # Reusing the existing SFTP session is MUCH faster than rclone copyto
            await self._backend.get_file(remote_path, local_path)
            
            # Start monitoring the directory to catch renames (atomic saves)
            self._start_edit_monitor(local_path, remote_path, item.name)
            
            if not use_chooser:
                # FAST: Launch application via Portal directly
                self._open_via_portal(local_path, ask=False)
            else:
                # REPLICA CHOOSER: Show custom app selection to avoid GNOME security smart design
                mime_type = self._get_mime_type(local_path)
                self._show_app_chooser(local_path, item.name, mime_type)
            
            GLib.idle_add(lambda: self._set_loading(False, _("Ready")))
        except Exception as exc:
            msg = str(exc)
            logger.error("Edit failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    def _get_mime_type(self, path: str) -> str:
        try:
            # 1. First try simple name/extension match
            f = Gio.File.new_for_path(path)
            info = f.query_info("standard::content-type", Gio.FileQueryInfoFlags.NONE, None)
            content_type = info.get_content_type()
            
            # 2. If it's generic octet-stream, try to sniff content for text
            if content_type in (None, "application/octet-stream", "application/x-zerosize", "unknown"):
                try:
                    with open(path, "rb") as bf:
                        chunk = bf.read(1024)
                        if chunk:
                            # Use GLib to guess from data
                            guessed_type, uncertainty = Gio.content_type_guess(path, chunk)
                            if not uncertainty:
                                content_type = guessed_type
                except Exception:
                    pass
            
            # 3. Text fallback for extensionless files (very common for development files like 'print', 'README')
            if content_type in (None, "application/octet-stream") and "." not in os.path.basename(path):
                content_type = "text/plain"
                
            return content_type or "application/octet-stream"
        except Exception:
            return "application/octet-stream"

    def _show_app_chooser(self, local_path: str, filename: str, mime_type: str) -> None:
        """Show a custom app chooser dialog to avoid Portal restrictions."""
        from views.dialogs import AppChooserReplica
        
        def _on_app_selected(app_info: Gio.AppInfo | None):
            if app_info:
                logger.info("SFTP: Selected app %s", app_info.get_name())
                try:
                    # Launch via our host bridge which handles portal sharing
                    self._launch_app_on_host_path(app_info, local_path)
                except Exception as e:
                    logger.error("SFTP: App launch failed: %s", e)
                    GLib.idle_add(lambda: self._set_loading(False, str(e)))
            else:
                # User chose "Use system chooser..." -> Fallback to Host Portal
                self._run_portal_fallback(local_path, True, mime_type)

        chooser = AppChooserReplica(
            self.get_root(), 
            filename, 
            mime_type, 
            _on_app_selected
        )
        chooser.present()

    def _open_selected(self, use_chooser: bool) -> None:
        item = self._get_selected()
        if item is None or item.is_dir:
            return
        self._run_async(self._do_edit(item, use_chooser=use_chooser))

    def _open_via_portal(self, local_path: str, ask: bool) -> None:
        """Professional bridge: Share via Document Portal to trigger Host-side Full Chooser."""
        logger.info("SFTP: Opening via Host Bridge %s (ask=%s)", local_path, ask)
        
        # Determine MIME hint
        content_type = "application/octet-stream"
        try:
            f = Gio.File.new_for_path(local_path)
            info = f.query_info("standard::content-type", Gio.FileQueryInfoFlags.NONE, None)
            content_type = info.get_content_type()
            if content_type in ("application/x-zerosize", "application/octet-stream"):
                guessed, _ = Gio.content_type_guess(local_path, None)
                if guessed: content_type = guessed
        except Exception: pass

        if not self._is_flatpak:
            # Native: just use standard portal
            self._do_call_portal_v3("", local_path, ask, content_type)
            return

        # ── Custom Application Chooser for Flatpak ──
        if ask:
             try:
                 GLib.idle_add(lambda: self._show_app_chooser(local_path, os.path.basename(local_path), content_type))
                 return
             except Exception as e:
                 logger.error("SFTP: Failed to show custom app chooser: %s", e)
                 # Fallback to portal below...
        
        try:
            # First, we need to add the file to the document portal
            fd = os.open(local_path, os.O_RDONLY)
            fd_list = Gio.UnixFDList.new_from_array([fd])
            
            conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            
            # org.freedesktop.portal.Documents.Add(o, b, b)
            # o: FD, b: reuse_existing, b: persistent
            var = GLib.Variant("(hbb)", (0, True, False))
            
            def _on_doc_added(obj, res):
                try:
                    out_var, _ = obj.call_with_unix_fd_list_finish(res)
                    doc_id = out_var.get_child_value(0).get_string()
                    logger.info("SFTP: Shared via Document Portal: %s", doc_id)
                    
                    # Construct the host-side path
                    # Document portal paths follow /run/user/$UID/doc/$DOC_ID/$BASENAME
                    import getpass
                    uid = os.getuid()
                    basename = os.path.basename(local_path)
                    host_path = f"/run/user/{uid}/doc/{doc_id}/{basename}"
                    
                    # Trigger host-side launch
                    import subprocess
                    if not ask:
                        # FAST TRACK: Just open with host's default
                        cmd = ["flatpak-spawn", "--host", "xdg-open", host_path]
                        subprocess.Popen(cmd)
                        logger.info("SFTP: Host-side default launch: %s", host_path)
                    else:
                        # Use host gdbus to trigger the Portal's own chooser on the host
                        # This is the "security smart design" part.
                        gdbus_cmd = [
                            "flatpak-spawn", "--host", "gdbus", "call", "--session",
                            "--dest", "org.freedesktop.portal.Desktop",
                            "--object-path", "/org/freedesktop/portal/desktop",
                            "--method", "org.freedesktop.portal.OpenURI.OpenURI",
                            "", # parent_window
                            f"file://{host_path}",
                            "{'ask': <true>}"
                        ]
                        subprocess.Popen(gdbus_cmd)
                        logger.info("SFTP: Host-side portal chooser triggered via gdbus: %s", host_path)

                except Exception as e:
                    logger.error("SFTP: Document Portal sharing failed: %s", e)
                    self._do_call_portal_v3("", local_path, ask, content_type)
                finally:
                    try: os.close(fd)
                    except OSError: pass

            conn.call_with_unix_fd_list(
                "org.freedesktop.portal.Documents",
                "/org/freedesktop/portal/documents",
                "org.freedesktop.portal.Documents",
                "Add",
                var,
                None,
                Gio.DBusCallFlags.NONE,
                -1,
                fd_list,
                None,
                _on_doc_added
            )
        except Exception as e:
            logger.error("SFTP: Bridge setup failed: %s", e)
            self._do_call_portal_v3("", local_path, ask, content_type)

    def _do_call_portal(self, handle: str, local_path: str, ask: bool, mime_type: str) -> None:
        import os
        fd = -1
        try:
            # Try high-privilege access first for editors
            try:
                fd = os.open(local_path, os.O_RDWR)
            except OSError:
                fd = os.open(local_path, os.O_RDONLY)

            fd_list = Gio.UnixFDList.new_from_array([fd])
            
            # The "secret" to the GNOME 50 full list is providing:
            # 1. Parent window handle
            # 2. explicit 'mime-type' hint (resolves "short list" issues)
            # 3. 'writable' flag (triggers editor prioritization)
            options = {
                "ask":       GLib.Variant("b", ask),
                "writable":  GLib.Variant("b", True),
                "mime-type": GLib.Variant("s", mime_type),
            }
            
            conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)

            def _on_call_done(obj, res):
                try:
                    obj.call_with_unix_fd_list_finish(res)
                    logger.info("SFTP: Portal OpenFile call sent")
                except Exception as e:
                    logger.error("SFTP: Portal OpenFile failed: %s", e)
                finally:
                    try: os.close(fd)
                    except OSError: pass

            conn.call_with_unix_fd_list(
                "org.freedesktop.portal.Desktop",
                "/org/freedesktop/portal/desktop",
                "org.freedesktop.portal.OpenURI",
                "OpenFile",
                GLib.Variant("(sha{sv})", (handle, 0, options)),
                None,
                Gio.DBusCallFlags.NONE,
                -1,
                fd_list,
                None,
                _on_call_done
            )
        except Exception as exc:
            logger.error("SFTP: Portal setup failed: %s", exc)
            if fd >= 0:
                try: os.close(fd)
                except OSError: pass
            self._fallback_open(local_path)

    def _fallback_open(self, local_path: str) -> None:
        import subprocess
        cmd = ["flatpak-spawn", "--host", "xdg-open", local_path] if self._is_flatpak else ["xdg-open", local_path]
        try:
            logger.info("SFTP: Fallback open triggered")
            subprocess.Popen(cmd)
        except Exception as e:
            logger.error("SFTP: Final fallback failed: %s", e)

    # ── Edit monitor ────────────────────────────────────────────────

    def _start_edit_monitor(
        self,
        local_path: str,
        remote_path: str,
        filename: str,
    ) -> None:
        if local_path in self._edit_sessions:
            return   # Already monitoring
        try:
            # We monitor the DIRECTORY to catch atomic saves (rename-over)
            directory = os.path.dirname(local_path)
            mon = Gio.File.new_for_path(directory).monitor_directory(
                Gio.FileMonitorFlags.WATCH_MOUNTS, None
            )
            session = EditSession(
                local_path=local_path,
                remote_path=remote_path,
                filename=filename,
                mtime=os.path.getmtime(local_path),
                monitor=mon,
                directory=directory,
            )
            mon.connect("changed", self._on_monitor_event, local_path)
            self._edit_sessions[local_path] = session
            logger.info("EditMonitor (DIR) started: %s -> %s", directory, remote_path)
        except Exception as exc:
            logger.error("Failed to start file monitor: %s", exc)

    def _on_monitor_event(
        self,
        _mon: Gio.FileMonitor,
        file: Gio.File,
        _other: Gio.File | None,
        event: Gio.FileMonitorEvent,
        local_path: str,
    ) -> None:
        # Since we monitor the directory, check if the changed file is ours
        if file.get_path() != local_path:
            return

        if event not in (
            Gio.FileMonitorEvent.CHANGES_DONE_HINT,
            Gio.FileMonitorEvent.CHANGED,
            Gio.FileMonitorEvent.CREATED,
            Gio.FileMonitorEvent.MOVED_IN,
        ):
            return
        session = self._edit_sessions.get(local_path)
        if session is None or session.pending:
            return
        try:
            new_mtime = os.path.getmtime(local_path)
        except OSError:
            return
        if new_mtime <= session.mtime:
            return
        session.mtime = new_mtime

        # Debounce: wait 1 second after the last change (reduced for better sync)
        if session.timer_id:
            GLib.source_remove(session.timer_id)

        session.timer_id = GLib.timeout_add(1000, self._on_debounce_timeout, local_path)

    def _on_debounce_timeout(self, local_path: str) -> bool:
        session = self._edit_sessions.get(local_path)
        if session:
            session.timer_id = 0
            self._prompt_or_auto_sync(local_path)
        return False

    def _prompt_or_auto_sync(self, local_path: str) -> None:
        session = self._edit_sessions.get(local_path)
        if session is None:
            return
        if self._auto_sync:
            self._do_sync_back(local_path)
            return
        session.pending = True
        from views.dialogs import prompt_confirmation
        prompt_confirmation(
            self.get_root(),
            _("File Changed"),
            _(f'Sync "{session.filename}" back to remote?'),
            _("Sync"),
            False,
            lambda yes: self._on_sync_decision(local_path, yes),
        )

    def _on_sync_decision(self, local_path: str, yes: bool) -> None:
        session = self._edit_sessions.get(local_path)
        if session:
            session.pending = False
        if yes:
            self._do_sync_back(local_path)

    def _do_sync_back(self, local_path: str) -> None:
        session = self._edit_sessions.get(local_path)
        if session is None:
            return
        self._set_loading(True, _("Syncing…"))

        async def _sync():
            try:
                await self._backend.put_file(session.local_path, session.remote_path)
                GLib.idle_add(lambda n=session.filename: self._set_loading(False, _(f"Synced {n}")))

                # Auto-refresh if the file belongs to the current directory
                remote_dir = os.path.dirname(session.remote_path)
                if remote_dir == self._current_path:
                    GLib.idle_add(lambda: self._load_path(self._current_path))
            except Exception as exc:
                msg = str(exc)
                logger.error("Sync-back failed: %s", msg)
                GLib.idle_add(lambda: self._set_loading(False, msg))

        self._run_async(_sync())

    def _sync_selected(self) -> None:
        """Manually trigger sync-back for the selected item."""
        item = self._get_selected()
        if item is None or item.is_dir:
            return
        full_path = os.path.join(self._current_path, item.name)
        for local_path, session in self._edit_sessions.items():
            if session.remote_path == full_path:
                self._do_sync_back(local_path)
                break

    # ── New file / folder ────────────────────────────────────────────

    def _new_entry(self, is_folder: bool) -> None:
        from views.dialogs import prompt_entry
        title = _("New Folder") if is_folder else _("New File")
        prompt_entry(
            self.get_root(), title, _("Name:"), "", _("Name"),
            lambda name: self._run_async(self._create_entry(name, is_folder)) if name else None,
        )

    async def _create_entry(self, name: str, is_folder: bool) -> None:
        path = os.path.join(self._current_path, name)
        GLib.idle_add(lambda: self._set_loading(True, _("Creating…")))
        try:
            if is_folder:
                await self._backend.mkdir(path)
            else:
                await self._backend.create_file(path)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            msg = str(exc)
            logger.error("create_entry failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    # ── Rename ──────────────────────────────────────────────────────

    def _rename_selected(self) -> None:
        item = self._get_selected()
        if item is None:
            return
        from views.dialogs import prompt_entry
        prompt_entry(
            self.get_root(), _("Rename"), item.name, item.name, _("New name"),
            lambda name: self._run_async(self._do_rename(item.name, name)) if name and name != item.name else None,
        )

    async def _do_rename(self, old_name: str, new_name: str) -> None:
        old = os.path.join(self._current_path, old_name)
        new = os.path.join(self._current_path, new_name)
        GLib.idle_add(lambda: self._set_loading(True, _("Renaming…")))
        try:
            await self._backend.rename(old, new)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            msg = str(exc)
            logger.error("rename failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    # ── Remove ──────────────────────────────────────────────────────

    def _remove_selected(self) -> None:
        item = self._get_selected()
        if item is None:
            return
        from views.dialogs import prompt_confirmation
        prompt_confirmation(
            self.get_root(), _("Remove"), item.name, _("Remove"), True,
            lambda yes: self._run_async(self._do_remove(item)) if yes else None,
        )

    async def _do_remove(self, item: SftpFile) -> None:
        path = os.path.join(self._current_path, item.name)
        GLib.idle_add(lambda: self._set_loading(True, _("Removing…")))
        try:
            await self._backend.remove(path, item.is_dir)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            msg = str(exc)
            logger.error("remove failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    # ── Download ────────────────────────────────────────────────────

    def _download_selected(self) -> None:
        item = self._get_selected()
        if item is None:
            return
        dlg = Gtk.FileDialog()
        if item.is_dir:
            dlg.select_folder(self.get_root(), None, self._on_folder_chosen, item)
        else:
            dlg.set_initial_name(item.name)
            dlg.save(self.get_root(), None, self._on_save_chosen, item)

    def _on_save_chosen(
        self, dlg: Gtk.FileDialog, result: Gio.AsyncResult, item: SftpFile
    ) -> None:
        try:
            gfile = dlg.save_finish(result)
        except Exception:
            return
        if gfile:
            remote = os.path.join(self._current_path, item.name)
            self._run_async(self._do_download(remote, gfile.get_path(), item.name))

    def _on_folder_chosen(
        self, dlg: Gtk.FileDialog, result: Gio.AsyncResult, item: SftpFile
    ) -> None:
        try:
            gfile = dlg.select_folder_finish(result)
        except Exception:
            return
        if gfile:
            dest = os.path.join(gfile.get_path(), item.name)
            remote = os.path.join(self._current_path, item.name)
            self._run_async(self._do_download(remote, dest, item.name))

    async def _do_download(
        self, remote_path: str, local_path: str, display_name: str
    ) -> None:
        GLib.idle_add(lambda: self._set_loading(True, _("Downloading…")))
        try:
            await self._backend.download(remote_path, local_path)
            GLib.idle_add(lambda: self._set_loading(False, _(f"Downloaded {display_name}")))
        except Exception as exc:
            msg = str(exc)
            logger.error("download failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    # ── Drag-and-drop upload ─────────────────────────────────────────

    def _on_dnd_drop(
        self,
        _target: Gtk.DropTarget,
        value: Any,
        _x: float,
        _y: float,
    ) -> bool:
        if isinstance(value, Gdk.FileList):
            files = value.get_files()
            if not files:
                return False
            paths = [f.get_path() for f in files if f.get_path()]
            if not paths:
                return False
            self._run_async(self._do_upload(paths))
            return True
        elif isinstance(value, GLib.Bytes):
            # Internal remote-to-remote drop
            try:
                data = json.loads(value.get_data().decode("utf-8"))
                source_conn_id = data.get("conn_id")
                remote_path    = data.get("remote_path")
                filename       = data.get("filename")
                
                if source_conn_id == self._conn.id:
                    # Same server, maybe move? For now just ignore or copy locally
                    # but logic is more complex for server-side copy.
                    return False
                
                self._run_async(self._do_remote_to_remote(source_conn_id, remote_path, filename))
                return True
            except Exception as exc:
                logger.error("Failed to parse DnD metadata: %s", exc)
                return False
        
        return False

    async def _do_remote_to_remote(self, source_conn_id: str, source_path: str, filename: str) -> None:
        """Transfer file from another server to this server using local relay."""
        GLib.idle_add(lambda: self._update_dnd_ui(True, filename))
        GLib.idle_add(lambda: self._set_loading(True, _("Transferring from another server…")))
        
        try:
            # 1. Find existing service or create temporary
            from views.terminal_view import TerminalTabView
            # We try to find the TabView from the widget tree
            # This is safer than the app.get_active_window hack
            tab_view = None
            parent = self.get_parent()
            while parent:
                # In our app, SftpTab is a child of the TabView's widget
                # Or we can check if the parent has the find_sftp_service method
                if hasattr(parent, "find_sftp_service"):
                    tab_view = parent
                    break
                # If not, maybe it's in the main window
                if parent.__class__.__name__ == "MainWindow" and hasattr(parent, "_terminal_tab_view"):
                    tab_view = parent._terminal_tab_view
                    break
                parent = parent.get_parent()
            
            source_svc = None
            if tab_view:
                source_svc = tab_view.find_sftp_service(source_conn_id)
            
            if not source_svc:
                # Fallback: Create a temporary service if the tab was closed
                db = Database()
                db.open()
                source_conn = db.get_connection(source_conn_id)
                db.close()
                if not source_conn:
                    raise Exception("Source connection not found")
                
                source_svc = SftpService(source_conn, self._ssh)
                # This might trigger UI for password if not cached
                await source_svc.connect({}) 
            
            # 2. Sequential transfer to avoid 0-byte issues
            relay_dir = os.path.join(GLib.get_user_cache_dir(), "sentinel", "relay")
            os.makedirs(relay_dir, exist_ok=True)
            local_relay = os.path.join(relay_dir, filename)
            
            # Download from source
            await source_svc.download(source_path, local_relay)
            
            # Upload to this destination
            await self._backend.upload([local_relay], self._current_path)
            
            # Clean up relay
            try: os.remove(local_relay)
            except OSError: pass
            
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            msg = str(exc)
            logger.error("SFTP Connect failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))
            return

        # Disable rclone mount - fully commented out to prevent fusermount3 errors
        # self._run_async(self._rclone.mount(self._conn.id, self._conn, self._backend.auth_info))
        
        GLib.idle_add(lambda: self._load_path(self._current_path))

    async def _do_upload(self, local_paths: list[str]) -> None:
        GLib.idle_add(lambda: self._set_loading(True, _("Uploading…")))
        try:
            await self._backend.upload(local_paths, self._current_path)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            msg = str(exc)
            logger.error("upload failed: %s", msg)
            GLib.idle_add(lambda: self._set_loading(False, msg))

    # ── Toggle actions ───────────────────────────────────────────────

    def _toggle_action(
        self, action: Gio.SimpleAction, _param, attr: str
    ) -> None:
        new_val = not getattr(self, attr)
        setattr(self, attr, new_val)
        action.set_state(GLib.Variant.new_boolean(new_val))
        if attr == "_show_hidden":
            self._refresh_store()
    def _launch_app_on_host_path(self, app_info: Gio.AppInfo, local_path: str) -> None:
        """Share with portal and then launch SPECIFIC app on host."""
        basename = os.path.basename(local_path)
        logger.info("SFTP: Preparing to launch host app %s on %s", app_info.get_name(), basename)
        
        try:
            fd = os.open(local_path, os.O_RDONLY)
            fd_list = Gio.UnixFDList.new_from_array([fd])
            conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            
            def _on_doc_added(obj, res):
                try:
                    out_var, _ = obj.call_with_unix_fd_list_finish(res)
                    doc_id = out_var.get_child_value(0).get_string()
                    uid = os.getuid()
                    host_path = f"/run/user/{uid}/doc/{doc_id}/{basename}"
                    
                    # Launch
                    exe = app_info.get_commandline().split(" %")[0].replace('"', "").strip()
                    logger.info("SFTP: Launching on host: %s %s", exe, host_path)
                    
                    import subprocess
                    subprocess.Popen(["flatpak-spawn", "--host", exe, host_path])
                except Exception as e:
                    logger.error("SFTP: Host launch preparation failed: %s", e)
                finally:
                    # In async callback, ensure we close the captured fd
                    try: os.close(fd or -1)
                    except OSError: pass

            conn.call_with_unix_fd_list(
                "org.freedesktop.portal.Documents", "/org/freedesktop/portal/documents",
                "org.freedesktop.portal.Documents", "Add",
                GLib.Variant("(hbb)", (0, True, False)),
                None, Gio.DBusCallFlags.NONE, -1, fd_list, None, _on_doc_added
            )
        except Exception as err:
            logger.error("Failed to share for host launch: %s", err)

    def _run_portal_fallback(self, local_path: str, ask: bool, content_type: str) -> None:
        """Actual fallback to host's own OpenURI portal."""
        # This repeats some of logic but is used for "Use system chooser..."
        try:
            fd = os.open(local_path, os.O_RDONLY)
            fd_list = Gio.UnixFDList.new_from_array([fd])
            conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            
            def _on_doc_added(obj, res):
                try:
                    out_var, _ = obj.call_with_unix_fd_list_finish(res)
                    doc_id = out_var.get_child_value(0).get_string()
                    uid = os.getuid()
                    basename = os.path.basename(local_path)
                    host_path = f"/run/user/{uid}/doc/{doc_id}/{basename}"
                    
                    import subprocess
                    gdbus_cmd = [
                        "flatpak-spawn", "--host", "gdbus", "call", "--session",
                        "--dest", "org.freedesktop.portal.Desktop",
                        "--object-path", "/org/freedesktop/portal/desktop",
                        "--method", "org.freedesktop.portal.OpenURI.OpenURI",
                        "", # parent_window
                        f"file://{host_path}",
                        "{'ask': <true>}"
                    ]
                    subprocess.Popen(gdbus_cmd)
                    logger.info("SFTP: Triggered host portal fallback for %s", host_path)
                except Exception as ex:
                    logger.error("Portal fallback failed: %s", ex)
                finally:
                    try: os.close(fd)
                    except OSError: pass

            conn.call_with_unix_fd_list(
                "org.freedesktop.portal.Documents", "/org/freedesktop/portal/documents",
                "org.freedesktop.portal.Documents", "Add",
                GLib.Variant("(hbb)", (0, True, False)),
                None, Gio.DBusCallFlags.NONE, -1, fd_list, None, _on_doc_added
            )
        except Exception: pass
