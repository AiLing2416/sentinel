# SPDX-License-Identifier: GPL-3.0-or-later

"""Chromium-style tab bar widget for GTK4 / libadwaita.

Provides a visually rich, Chromium-inspired tab strip that works with
Adw.TabView for the underlying page management.

Key features:
 - Trapezoidal / rounded tab shape via CSS
 - Active tab visually raised above strip
 - Each tab has an icon, title (ellipsized), and close button
 - "New Tab" (+) button at the end
 - Tabs squeeze to fit the available width
 - Middle-click to close, right-click context menu
 - Smooth hover / active transitions
 - Drag-reorder support
"""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk  # noqa: E402


class _DragState:
    page: Adw.TabPage | None = None
    source_view: Adw.TabView | None = None

_drag_state = _DragState()

# ── Single Tab Widget ────────────────────────────────────────────────────────


class ChromeTab(Gtk.Box):
    """A single tab in the Chromium-style tab bar.

    Visual structure:
      ┌──────────────────────────────────────┐
      │ [icon]  Title…              [✕]      │
      └──────────────────────────────────────┘
    """

    def __init__(
        self,
        page: Adw.TabPage,
        tab_view: Adw.TabView,
        on_activate: Callable[[Adw.TabPage], None],
        on_close: Callable[[Adw.TabPage], None],
        on_create_window: Callable[[], Adw.TabView | None] | None = None,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._page = page
        self._tab_view = tab_view
        self._on_activate_cb = on_activate
        self._on_close_cb = on_close
        self._on_create_window_cb = on_create_window
        self._selected = False

        self.add_css_class("chrome-tab")
        self.set_can_focus(False)  # Tab bar itself shouldn't steal terminal focus

        self._build_content()
        self._connect_signals()

    @property
    def page(self) -> Adw.TabPage:
        return self._page

    @property
    def selected(self) -> bool:
        return self._selected

    @selected.setter
    def selected(self, value: bool) -> None:
        self._selected = value
        if value:
            self.add_css_class("active")
        else:
            self.remove_css_class("active")

    # ── Build ──────────────────────────────────────────────

    def _build_content(self) -> None:
        # Tab icon
        self._icon = Gtk.Image()
        icon = self._page.get_icon()
        if icon:
            self._icon.set_from_gicon(icon)
        self._icon.set_pixel_size(16)
        self._icon.add_css_class("chrome-tab-icon")
        self.append(self._icon)

        # Tab title (ellipsized)
        self._label = Gtk.Label(
            label=self._page.get_title() or "Untitled",
            xalign=0,
            hexpand=True,
            ellipsize=3,  # PANGO_ELLIPSIZE_END
            single_line_mode=True,
        )
        self._label.add_css_class("chrome-tab-label")
        self.append(self._label)

        # Loading spinner (shown while page is loading)
        self._spinner = Gtk.Spinner()
        self._spinner.set_size_request(14, 14)
        self._spinner.set_visible(False)
        self.append(self._spinner)

        # Close button
        self._close_btn = Gtk.Button(icon_name="window-close-symbolic")
        self._close_btn.add_css_class("chrome-tab-close")
        self._close_btn.add_css_class("flat")
        self._close_btn.add_css_class("circular")
        self._close_btn.set_valign(Gtk.Align.CENTER)
        self._close_btn.set_can_focus(False)
        self._close_btn.set_tooltip_text("Close tab")
        self._close_btn.connect("clicked", self._on_close_clicked)
        self.append(self._close_btn)

    def _connect_signals(self) -> None:
        # Click to activate
        left_click = Gtk.GestureClick(button=1)
        left_click.connect("pressed", self._on_tab_clicked)
        self.add_controller(left_click)

        # Middle-click to close
        middle_click = Gtk.GestureClick(button=2)
        middle_click.connect("pressed", self._on_middle_click)
        self.add_controller(middle_click)

        # Listen for page property changes
        self._page.connect("notify::title", self._on_page_title_changed)
        self._page.connect("notify::icon", self._on_page_icon_changed)
        self._page.connect("notify::loading", self._on_page_loading_changed)

        # Drag Source (Initiate drag)
        self._drag_source = Gtk.DragSource()
        self._drag_source.set_actions(Gdk.DragAction.MOVE)
        self._drag_source.connect("prepare", self._on_drag_prepare)
        self._drag_source.connect("drag-begin", self._on_drag_begin)
        self._drag_source.connect("drag-cancel", self._on_drag_cancel)
        self._drag_source.connect("drag-end", self._on_drag_end)
        self.add_controller(self._drag_source)
        
        # Drop Target (For reordering between tabs)
        self._drop_target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.MOVE)
        self._drop_target.connect("drop", self._on_drop)
        self.add_controller(self._drop_target)

    # ── Event Handlers ─────────────────────────────────────

    def _on_tab_clicked(self, gesture: Gtk.GestureClick, n_press: int, x: float, y: float) -> None:
        self._on_activate_cb(self._page)

    def _on_close_clicked(self, _btn: Gtk.Button) -> None:
        self._on_close_cb(self._page)

    def _on_middle_click(
        self,
        gesture: Gtk.GestureClick,
        n_press: int,
        x: float,
        y: float,
    ) -> None:
        self._on_close_cb(self._page)

    def _on_page_title_changed(self, page: Adw.TabPage, _pspec) -> None:  # noqa: ANN001
        self._label.set_label(page.get_title() or "Untitled")

    def _on_page_icon_changed(self, page: Adw.TabPage, _pspec) -> None:  # noqa: ANN001
        icon = page.get_icon()
        if icon:
            self._icon.set_from_gicon(icon)

    def _on_page_loading_changed(self, page: Adw.TabPage, _pspec) -> None:  # noqa: ANN001
        loading = page.get_loading()
        self._spinner.set_visible(loading)
        self._spinner.set_spinning(loading)
        self._icon.set_visible(not loading)

    def _on_drag_prepare(self, source: Gtk.DragSource, x: float, y: float) -> Gdk.ContentProvider | None:
        _drag_state.page = self._page
        _drag_state.source_view = self._tab_view
        
        # We can snapshot the widget to show an icon during dragging
        # source.set_icon(Gtk.WidgetPaintable.new(self), x, y)
        value = GObject.Value(GObject.TYPE_STRING, "sentinel-tab")
        return Gdk.ContentProvider.new_for_value(value)

    def _on_drag_begin(self, source: Gtk.DragSource, drag: Gdk.Drag) -> None:
        self.add_css_class("dragging")

    def _on_drag_cancel(self, source: Gtk.DragSource, drag: Gdk.Drag, reason: Gdk.DragCancelReason) -> bool:
        if reason == Gdk.DragCancelReason.NO_TARGET and _drag_state.page and _drag_state.source_view:
            if self._on_create_window_cb:
                new_view = self._on_create_window_cb()
                if new_view:
                    _drag_state.source_view.transfer_page(_drag_state.page, new_view, 0)
                    return True
        return False

    def _on_drag_end(self, source: Gtk.DragSource, drag: Gdk.Drag, delete_data: bool) -> None:
        self.remove_css_class("dragging")
        _drag_state.page = None
        _drag_state.source_view = None

    def _on_drop(self, target: Gtk.DropTarget, value: Any, x: float, y: float) -> bool:
        if value != "sentinel-tab" or not _drag_state.page or not _drag_state.source_view:
            return False
            
        target_pos = self._tab_view.get_page_position(self._page)
        
        if _drag_state.source_view == self._tab_view:
            self._tab_view.reorder_page(_drag_state.page, target_pos)
        else:
            _drag_state.source_view.transfer_page(_drag_state.page, self._tab_view, target_pos)
            
        return True

    # ── Public API ─────────────────────────────────────────

    def update_from_page(self) -> None:
        """Re-sync visual state from the underlying page."""
        self._label.set_label(self._page.get_title() or "Untitled")
        icon = self._page.get_icon()
        if icon:
            self._icon.set_from_gicon(icon)


# ── Chrome Tab Bar ───────────────────────────────────────────────────────────


class ChromeTabBar(Gtk.Box):
    """Chromium-style tab strip that drives an Adw.TabView.

    Layout:
      [ tab1 | tab2 | tab3 | ... | + ]

    Sits inside a custom header replacing the default Adw.HeaderBar on the
    content side of the split view.
    """

    def __init__(
        self,
        tab_view: Adw.TabView,
        on_new_tab: Callable[[], None] | None = None,
        on_create_window: Callable[[], Adw.TabView | None] | None = None,
    ) -> None:
        super().__init__(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=0,
        )
        self.add_css_class("chrome-tab-bar")
        self.set_hexpand(True)

        self._tab_view = tab_view
        self._on_new_tab = on_new_tab
        self._on_create_window = on_create_window
        self._tab_widgets: dict[Adw.TabPage, ChromeTab] = {}

        self._build_ui()
        self._connect_tab_view_signals()
        self._sync_all_tabs()

    # ── Build ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Tab container — hexpand=False prevents the label's hexpand from
        # propagating up and competing with the drag spacer for space.
        self._tab_box = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=1,
            homogeneous=True,  # Equal-width tabs, Chromium-like
            hexpand=False,
        )
        self._tab_box.add_css_class("chrome-tab-box")
        self.append(self._tab_box)

        # Internal drag spacer — fills remaining header space for window dragging
        self._drag_spacer = Gtk.Box(hexpand=True)
        self._drag_spacer.add_css_class("chrome-drag-spacer")
        
        # Drop Target on spacer (For dropping at the end of the tabs)
        self._drop_target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.MOVE)
        self._drop_target.connect("drop", self._on_spacer_drop)
        self._drag_spacer.add_controller(self._drop_target)
        
        self.append(self._drag_spacer)

    # ── Tab View signals ───────────────────────────────────

    def _connect_tab_view_signals(self) -> None:
        self._tab_view.connect("page-attached", self._on_page_attached)
        self._tab_view.connect("page-detached", self._on_page_detached)
        self._tab_view.connect("page-reordered", self._on_page_reordered)
        self._tab_view.connect("notify::selected-page", self._on_selected_changed)

    def _sync_all_tabs(self) -> None:
        """Sync tab widgets with tab view pages (initial population)."""
        for i in range(self._tab_view.get_n_pages()):
            page = self._tab_view.get_nth_page(i)
            self._add_tab_widget(page, i)
        self._update_selection()

    # ── Tab management ─────────────────────────────────────

    def _add_tab_widget(self, page: Adw.TabPage, position: int = -1) -> None:
        tab = ChromeTab(
            page=page,
            tab_view=self._tab_view,
            on_activate=self._activate_page,
            on_close=self._close_page,
            on_create_window=self._on_create_window,
        )
        self._tab_widgets[page] = tab

        if position < 0:
            # Append at end
            self._tab_box.append(tab)
        elif position == 0:
            # Prepend at start
            self._tab_box.prepend(tab)
        else:
            # Insert after the widget at (position - 1)
            children = self._tab_box.observe_children()
            n = children.get_n_items()
            if position <= n:
                sibling = children.get_item(position - 1)
                self._tab_box.insert_child_after(tab, sibling)
            else:
                self._tab_box.append(tab)
        self._update_selection()

    def _remove_tab_widget(self, page: Adw.TabPage) -> None:
        tab = self._tab_widgets.pop(page, None)
        if tab:
            self._tab_box.remove(tab)

    def _update_selection(self) -> None:
        selected = self._tab_view.get_selected_page()
        for page, tab in self._tab_widgets.items():
            tab.selected = page == selected

    # ── Callbacks ──────────────────────────────────────────

    def _activate_page(self, page: Adw.TabPage) -> None:
        self._tab_view.set_selected_page(page)

    def _close_page(self, page: Adw.TabPage) -> None:
        self._tab_view.close_page(page)

    def _on_new_tab_clicked(self, _btn: Gtk.Button) -> None:
        if self._on_new_tab:
            self._on_new_tab()

    def _on_spacer_drop(self, target: Gtk.DropTarget, value: Any, x: float, y: float) -> bool:
        if value != "sentinel-tab" or not _drag_state.page or not _drag_state.source_view:
            return False
            
        n_pages = self._tab_view.get_n_pages()
        if _drag_state.source_view == self._tab_view:
            self._tab_view.reorder_page(_drag_state.page, n_pages)
        else:
            _drag_state.source_view.transfer_page(_drag_state.page, self._tab_view, n_pages)
            
        return True

    def _on_page_attached(
        self, tab_view: Adw.TabView, page: Adw.TabPage, position: int
    ) -> None:
        self._add_tab_widget(page, position)

    def _on_page_detached(
        self, tab_view: Adw.TabView, page: Adw.TabPage, position: int
    ) -> None:
        self._remove_tab_widget(page)

    def _on_page_reordered(
        self, tab_view: Adw.TabView, page: Adw.TabPage, position: int
    ) -> None:
        # Re-order: remove + re-insert at new position
        tab = self._tab_widgets.get(page)
        if tab:
            self._tab_box.remove(tab)
            if position > 0:
                prev_page = self._tab_view.get_nth_page(position - 1)
                prev_tab = self._tab_widgets.get(prev_page)
                self._tab_box.insert_child_after(tab, prev_tab)
            else:
                self._tab_box.prepend(tab)

    def _on_selected_changed(self, tab_view: Adw.TabView, _pspec) -> None:  # noqa: ANN001
        self._update_selection()

    # ── Public API ─────────────────────────────────────────

    @property
    def tab_view(self) -> Adw.TabView:
        return self._tab_view
