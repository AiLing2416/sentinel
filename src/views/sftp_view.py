# SPDX-License-Identifier: GPL-3.0-or-later

"""SFTP file-browser view — rewrote from scratch for Sentinel v0.3."""

from __future__ import annotations

import gettext
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

from models.connection import Connection
from services.async_engine import call_ui_sync
from services.rclone_service import RcloneService
from services.sftp_service import SftpService
from services.ssh_service import SSHService

_ = gettext.gettext
logger = logging.getLogger(__name__)

MAX_DIRECT_EDIT_BYTES = 200 * 1024 * 1024   # 200 MB soft limit


# ---------------------------------------------------------------------------
# GObject model for the ColumnView
# ---------------------------------------------------------------------------

class SftpFile(GObject.Object):
    """GObject wrapper around a remote file entry for use with Gtk.ColumnView."""

    name        = GObject.Property(type=str,  default="")
    size        = GObject.Property(type=int,  default=0)
    mtime       = GObject.Property(type=int,  default=0)
    is_dir      = GObject.Property(type=bool, default=False)
    permissions = GObject.Property(type=int,  default=0)
    uid         = GObject.Property(type=int,  default=0)
    gid         = GObject.Property(type=int,  default=0)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

    @property
    def icon_name(self) -> str:
        return "folder-symbolic" if self.is_dir else "text-x-generic-symbolic"

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
    pending:     bool = False           # True while a sync-confirm dialog is open


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

        self._current_path = "."
        self._history:       list[str] = []
        self._history_idx:   int       = -1
        self._all_items:     list[SftpFile] = []
        self._edit_sessions: dict[str, EditSession] = {}   # keyed by local_path
        self._show_hidden  = False
        self._auto_sync    = False

        self._store = Gio.ListStore.new(SftpFile)
        self._build_ui()
        self._run_async(self._do_connect())

    # ── Public lifecycle ────────────────────────────────────────────

    def terminate(self) -> None:
        """Clean up monitors, temp files, FUSE mount and SSH connection."""
        logger.info("SftpTab[%s]: terminating", self._conn.hostname)
        for es in list(self._edit_sessions.values()):
            es.monitor.cancel()
        self._edit_sessions.clear()
        self._run_async(self._rclone.unmount(self._conn.id))
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

        # Drag-and-drop upload
        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
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
        edit_sec.append(_("Delete"), "sftp.delete")
        m.append_section(None, edit_sec)
        xfer_sec = Gio.Menu()
        xfer_sec.append(_("Download…"), "sftp.download")
        m.append_section(None, xfer_sec)
        return m

    def _register_actions(self) -> None:
        simple = [
            ("open",       lambda *_: self._open_selected(use_chooser=False)),
            ("open-with",  lambda *_: self._open_selected(use_chooser=True)),
            ("rename",     lambda *_: self._rename_selected()),
            ("delete",     lambda *_: self._delete_selected()),
            ("download",   lambda *_: self._download_selected()),
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

    @staticmethod
    def _setup_name_cell(_f, li: Gtk.ListItem) -> None:
        box = Gtk.Box(spacing=8)
        box.append(Gtk.Image())
        label = Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)
        label.set_hexpand(True)
        box.append(label)
        li.set_child(box)

    @staticmethod
    def _bind_name_cell(_f, li: Gtk.ListItem) -> None:
        item: SftpFile = li.get_item()
        box = li.get_child()
        box.get_first_child().set_from_icon_name(item.icon_name)
        box.get_first_child().get_next_sibling().set_text(item.name)

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
            self._status_lbl.set_text(message)

    def _set_status(self, msg: str) -> None:
        self._status_lbl.set_text(msg)

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

        cbs = {
            "ask_password":    lambda c, r: prompt_password(self.get_root(), _("Password"), c.hostname, r),
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
        # Start FUSE mount in background (best-effort; failure is non-fatal)
        self._run_async(self._ensure_mount())

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
        for name in ("open", "open-with", "rename", "delete", "download"):
            act = self._ag.lookup_action(name)
            if act:
                act.set_enabled(has)
        r = Gdk.Rectangle()
        r.x, r.y, r.width, r.height = int(x), int(y), 1, 1
        self._pop.set_pointing_to(r)
        self._pop.popup()

    # ── Open / Edit ─────────────────────────────────────────────────

    def _open_selected(self, use_chooser: bool) -> None:
        item = self._get_selected()
        if item is None or item.is_dir:
            return
        remote = os.path.join(self._current_path, item.name)

        if item.size > MAX_DIRECT_EDIT_BYTES:
            from views.dialogs import prompt_confirmation
            prompt_confirmation(
                self.get_root(), _("Large File Warning"),
                _("This file is very large. Open anyway?"), _("Open"), False,
                lambda yes: self._run_async(self._fetch_for_edit(remote, item, use_chooser)) if yes else None,
            )
        else:
            self._run_async(self._fetch_for_edit(remote, item, use_chooser))

    async def _fetch_for_edit(
        self,
        remote_path: str,
        item: SftpFile,
        use_chooser: bool,
    ) -> None:
        """Download *remote_path* via rclone, then open with default app."""
        GLib.idle_add(lambda: self._set_loading(True, _("Downloading for edit…")))
        local_path, err = await self._rclone.download_for_edit(
            self._conn, self._backend.auth_info, remote_path
        )
        if err or not local_path:
            GLib.idle_add(lambda: self._set_loading(False, err or _("Download failed")))
            return
        GLib.idle_add(lambda: self._launch_edit(local_path, remote_path, item, use_chooser))

    def _launch_edit(
        self,
        local_path: str,
        remote_path: str,
        item: SftpFile,
        use_chooser: bool,
    ) -> None:
        self._set_loading(False)
        gfile = Gio.File.new_for_path(local_path)

        def _after_launch() -> None:
            self._start_edit_monitor(local_path, remote_path, item.name)

        try:
            if use_chooser:
                try:
                    ct = gfile.query_info("standard::content-type", 0, None).get_content_type()
                except Exception:
                    ct = "application/octet-stream"
                dlg = Gtk.AppChooserDialog.new_for_content_type(self.get_root(), 0, ct)
                dlg.connect("response", self._on_chooser_response, local_path, remote_path, item.name)
                dlg.present()
            else:
                handler = gfile.query_default_handler(None)
                if handler:
                    handler.launch([gfile], None)
                else:
                    Gio.AppInfo.launch_default_for_uri(gfile.get_uri(), None)
                _after_launch()
        except Exception as exc:
            logger.error("_launch_edit: %s", exc)
            self._set_status(str(exc))

    def _on_chooser_response(
        self, dlg: Gtk.AppChooserDialog, resp: int,
        local_path: str, remote_path: str, filename: str,
    ) -> None:
        if resp == Gtk.ResponseType.OK:
            app = dlg.get_app_info()
            if app:
                gfile = Gio.File.new_for_path(local_path)
                app.launch([gfile], None)
                self._start_edit_monitor(local_path, remote_path, filename)
        dlg.destroy()

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
            mon = Gio.File.new_for_path(local_path).monitor_file(
                Gio.FileMonitorFlags.NONE, None
            )
            session = EditSession(
                local_path=local_path,
                remote_path=remote_path,
                filename=filename,
                mtime=os.path.getmtime(local_path),
                monitor=mon,
            )
            mon.connect("changed", self._on_monitor_event, local_path)
            self._edit_sessions[local_path] = session
            logger.info("EditMonitor started: %s -> %s", local_path, remote_path)
        except Exception as exc:
            logger.error("Failed to start file monitor: %s", exc)

    def _on_monitor_event(
        self,
        _mon: Gio.FileMonitor,
        _file: Gio.File,
        _other: Gio.File | None,
        event: Gio.FileMonitorEvent,
        local_path: str,
    ) -> None:
        if event not in (
            Gio.FileMonitorEvent.CHANGES_DONE_HINT,
            Gio.FileMonitorEvent.CHANGED,
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
        GLib.idle_add(self._prompt_or_auto_sync, local_path)

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
            except Exception as exc:
                logger.error("Sync-back failed: %s", exc)
                GLib.idle_add(lambda: self._set_loading(False, str(exc)))

        self._run_async(_sync())

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
            logger.error("create_entry failed: %s", exc)
            GLib.idle_add(lambda: self._set_loading(False, str(exc)))

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
            logger.error("rename failed: %s", exc)
            GLib.idle_add(lambda: self._set_loading(False, str(exc)))

    # ── Delete ──────────────────────────────────────────────────────

    def _delete_selected(self) -> None:
        item = self._get_selected()
        if item is None:
            return
        from views.dialogs import prompt_confirmation
        prompt_confirmation(
            self.get_root(), _("Delete"), item.name, _("Delete"), True,
            lambda yes: self._run_async(self._do_delete(item)) if yes else None,
        )

    async def _do_delete(self, item: SftpFile) -> None:
        path = os.path.join(self._current_path, item.name)
        GLib.idle_add(lambda: self._set_loading(True, _("Deleting…")))
        try:
            await self._backend.remove(path, item.is_dir)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            logger.error("delete failed: %s", exc)
            GLib.idle_add(lambda: self._set_loading(False, str(exc)))

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
            logger.error("download failed: %s", exc)
            GLib.idle_add(lambda: self._set_loading(False, str(exc)))

    # ── Drag-and-drop upload ─────────────────────────────────────────

    def _on_dnd_drop(
        self,
        _target: Gtk.DropTarget,
        value: Gdk.FileList,
        _x: float,
        _y: float,
    ) -> bool:
        files = value.get_files()
        if not files:
            return False
        paths = [f.get_path() for f in files if f.get_path()]
        if not paths:
            return False
        self._run_async(self._do_upload(paths))
        return True

    async def _do_upload(self, local_paths: list[str]) -> None:
        GLib.idle_add(lambda: self._set_loading(True, _("Uploading…")))
        try:
            await self._backend.upload(local_paths, self._current_path)
            GLib.idle_add(lambda: self._load_path(self._current_path))
        except Exception as exc:
            logger.error("upload failed: %s", exc)
            GLib.idle_add(lambda: self._set_loading(False, str(exc)))

    # ── Toggle actions ───────────────────────────────────────────────

    def _toggle_action(
        self, action: Gio.SimpleAction, _param, attr: str
    ) -> None:
        new_val = not getattr(self, attr)
        setattr(self, attr, new_val)
        action.set_state(GLib.Variant.new_boolean(new_val))
        if attr == "_show_hidden":
            self._refresh_store()
