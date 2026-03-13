#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Sentinel — GNOME SSH Connection Manager

"""Application entry point."""

import os
import sys

# Allow running from source tree during development
_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from application import SentinelApplication  # noqa: E402


def _setup_language() -> None:
    import gettext
    import locale
    from db.database import Database

    db = Database()
    db.open()
    lang_code = db.get_meta("app_language", "")
    db.close()

    domain = 'sentinel'
    localedir = os.path.join(_src_dir, '..', 'build', 'po')

    if lang_code:
        os.environ['LANGUAGE'] = lang_code
        try:
            locale.setlocale(locale.LC_ALL, f"{lang_code}.UTF-8")
        except locale.Error:
            pass

    # Initialize gettext for Python side
    gettext.bindtextdomain(domain, localedir)
    gettext.textdomain(domain)
    # The C components (like GLib/Gtk) will automatically pick up the LANGUAGE env var


def main() -> int:
    """Launch the Sentinel application."""
    _setup_language()
    app = SentinelApplication()
    ret = app.run(sys.argv)

    try:
        from services.rclone_service import RcloneService
        RcloneService.get().unmount_all()
    except Exception as e:
        import logging
        logging.error(f"Failed to unmount active FUSE directories: {e}")

    return ret


if __name__ == "__main__":
    sys.exit(main())
