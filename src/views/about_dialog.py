# SPDX-License-Identifier: GPL-3.0-or-later

"""Custom About Sentinel dialog containing check update controls."""

from __future__ import annotations

import gettext
import logging
from typing import Any

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk, GLib

from db.database import Database
from services.async_engine import call_ui_sync, AsyncEngine
from services.updater import UpdaterService

_ = gettext.gettext
logger = logging.getLogger(__name__)

VERSION = "0.3.1"

class SentinelAboutDialog(Adw.Window):
    """Custom About window styled like Adw.AboutDialog with check-update features."""

    def __init__(self, parent: Gtk.Window) -> None:
        super().__init__(
            modal=True,
            transient_for=parent,
            title=_("About Sentinel"),
            default_width=420,
            default_height=600,
        )

        self._updater = UpdaterService.get()
        
        # Load update mode from DB
        db = Database()
        db.open()
        try:
            self._update_mode = db.get_meta("update_mode", "check_only")
        finally:
            db.close()

        self._build_ui()

    def _build_ui(self) -> None:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        
        # Header bar
        header = Adw.HeaderBar()
        box.append(header)
        
        # Inner content box
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(24)
        content.set_margin_bottom(24)
        content.set_margin_start(24)
        content.set_margin_end(24)
        
        # Logo - Load Sentinel.svg from file in dev mode, or via themed icon in production Flatpak
        import os
        dev_icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Sentinel.svg"))
        if not os.path.exists(dev_icon_path):
            dev_icon_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Sentinel.svg"))
            
        logo = Gtk.Image()
        if os.path.exists(dev_icon_path):
            logo.set_from_file(dev_icon_path)
            logo.set_property("pixel-size", 96)
        else:
            logo.set_from_icon_name("io.github.ailing2416.sentinel")
            logo.set_property("pixel-size", 96)
        content.append(logo)
        
        # Title
        title_label = Gtk.Label()
        title_label.add_css_class("title-1")
        title_label.set_markup("<span weight='bold' size='x-large'>Sentinel</span>")
        content.append(title_label)
        
        # Version
        self._version_label = Gtk.Label(label=f"Version {VERSION}")
        self._version_label.add_css_class("dim-label")
        self._version_label.add_css_class("subtitle")
        content.append(self._version_label)
        
        # Website
        website_btn = Gtk.LinkButton.new_with_label("https://github.com/AiLing2416/sentinel", _("Website"))
        website_btn.set_halign(Gtk.Align.CENTER)
        content.append(website_btn)
        
        # Separator
        content.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
        
        # Preferences Group for Updates
        prefs_group = Adw.PreferencesGroup()
        prefs_group.set_title(_("Updates"))
        content.append(prefs_group)
        
        # Update Mode Row
        self._mode_row = Adw.ComboRow()
        self._mode_row.set_title(_("Update Mode"))
        self._mode_row.set_subtitle(_("Choose update action"))
        
        self._mode_options = Gtk.StringList.new([
            _("Check Only"),
            _("Check and Install")
        ])
        self._mode_row.set_model(self._mode_options)
        self._mode_row.set_selected(1 if self._update_mode == "check_and_install" else 0)
        self._mode_row.connect("notify::selected", self._on_mode_changed)
        prefs_group.add(self._mode_row)
        
        # Action Row for Check Now
        check_row = Adw.ActionRow()
        check_row.set_title(_("Check for Updates"))
        check_row.set_subtitle(_("Check GitHub Releases for updates"))
        
        self._check_btn = Gtk.Button(label=_("Check Now"))
        self._check_btn.set_valign(Gtk.Align.CENTER)
        self._check_btn.add_css_class("flat")
        self._check_btn.connect("clicked", self._on_check_clicked)
        check_row.add_suffix(self._check_btn)
        prefs_group.add(check_row)
        
        # Status Row
        self._status_row = Adw.ActionRow()
        self._status_row.set_title(_("Status"))
        self._status_label = Gtk.Label(label=_("Unknown"))
        self._status_label.set_halign(Gtk.Align.END)
        self._status_row.add_suffix(self._status_label)
        prefs_group.add(self._status_row)
        
        # Progress Bar (initially hidden)
        self._progress_bar = Gtk.ProgressBar()
        self._progress_bar.set_visible(False)
        self._progress_bar.set_margin_start(6)
        self._progress_bar.set_margin_end(6)
        content.append(self._progress_bar)
        
        # Copyright
        copyright_label = Gtk.Label(
            label=_("© 2026 Sentinel Contributors\nLicensed under GPL-3.0")
        )
        copyright_label.add_css_class("dim-label")
        copyright_label.add_css_class("caption")
        copyright_label.set_justify(Gtk.Justification.CENTER)
        copyright_label.set_margin_top(16)
        content.append(copyright_label)
        
        box.append(content)
        self.set_content(box)

    def _on_mode_changed(self, combo_row: Adw.ComboRow, _pspec: Any) -> None:
        selected = combo_row.get_selected()
        self._update_mode = "check_and_install" if selected == 1 else "check_only"
        
        db = Database()
        db.open()
        try:
            db.set_meta("update_mode", self._update_mode)
        finally:
            db.close()
        logger.info("Saved update mode: %s", self._update_mode)

    def _on_check_clicked(self, _btn: Gtk.Button) -> None:
        self._check_btn.set_sensitive(False)
        self._mode_row.set_sensitive(False)
        self._status_label.set_text(_("Checking for updates..."))
        self._progress_bar.set_visible(False)
        self._progress_bar.set_fraction(0.0)
        
        # Submit update check task to AsyncEngine
        engine = AsyncEngine.get()
        engine.run_coroutine(self._do_update_check())

    async def _do_update_check(self) -> None:
        result = await self._updater.check_update(VERSION)
        
        status = result.get("status")
        latest_version = result.get("latest_version", "")
        
        if status == "error":
            err = result.get("error_message", "")
            if err == "network_error":
                msg = _("Failed to connect to GitHub.")
            else:
                msg = _("Check failed: {err}").format(err=err)
            call_ui_sync(self._update_ui_finished, msg)
            
        elif status == "latest":
            msg = _("You are running the latest version.")
            call_ui_sync(self._update_ui_finished, msg)
            
        elif status == "beta_version":
            msg = _("Beta version (latest release: {v})").format(v=latest_version)
            call_ui_sync(self._update_ui_finished, msg)
            
        elif status == "update_available":
            download_url = result.get("download_url")
            if self._update_mode == "check_only":
                msg = _("New version {v} available!").format(v=latest_version)
                call_ui_sync(self._update_ui_finished, msg)
            else:
                # Check installation environment for check and install mode
                if not self._updater.is_flatpak():
                    msg = _("Error: Not a Flatpak environment.")
                    call_ui_sync(self._update_ui_finished, msg)
                elif not self._updater.is_user_installation():
                    msg = _("Error: System Flatpak detected. Only user Flatpak supports auto-update.")
                    call_ui_sync(self._update_ui_finished, msg)
                elif not download_url:
                    msg = _("Error: No matching package found.")
                    call_ui_sync(self._update_ui_finished, msg)
                else:
                    # Proceed to download and install
                    call_ui_sync(self._start_download_ui, latest_version)
                    try:
                        def progress_cb(fraction: float):
                            call_ui_sync(self._update_download_progress, fraction)
                            
                        await self._updater.download_and_install(download_url, progress_cb)
                        call_ui_sync(self._update_ui_finished, _("Install complete! Please restart Sentinel."))
                    except Exception as e:
                        msg = _("Installation failed: {err}").format(err=str(e))
                        call_ui_sync(self._update_ui_finished, msg)

    def _start_download_ui(self, version: str) -> None:
        self._status_label.set_text(_("Downloading version {v}...").format(v=version))
        self._progress_bar.set_visible(True)
        self._progress_bar.set_fraction(0.0)

    def _update_download_progress(self, fraction: float) -> None:
        self._progress_bar.set_fraction(fraction)
        if fraction >= 1.0:
            self._status_label.set_text(_("Installing..."))

    def _update_ui_finished(self, message: str) -> None:
        self._status_label.set_text(message)
        self._check_btn.set_sensitive(True)
        self._mode_row.set_sensitive(True)
        self._progress_bar.set_visible(False)
