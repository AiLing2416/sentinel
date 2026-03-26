#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Sentinel — GNOME SSH Connection Manager

"""Application entry point."""

import os
import sys
import logging

# Allow running from source tree during development
_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)
def _setup_language() -> None:
    import gettext
    import locale
    from db.database import Database

    db = Database()
    db.open()
    lang_code = db.get_meta("app_language", "")
    db.close()

    domain = 'sentinel'
    # Development: .mo files are compiled to build/locale/ by run_dev.sh
    localedir = os.path.join(_src_dir, '..', 'build', 'locale')
    if not os.path.isdir(localedir):
        # Fallback: system-installed location
        localedir = os.path.join(_src_dir, '..', 'build', 'po')

    # Load customized UI language configuration
    if lang_code:
        os.environ['LANGUAGE'] = lang_code
        try:
            # Create a static Translation object for the requested language
            t = gettext.translation(domain, localedir, languages=[lang_code], fallback=True)
            # Monkey-patch the global gettext module to bypass all system/portal restrictions!
            gettext.gettext = t.gettext
            
            # Optionally attempt to set the C locale as well
            locale.setlocale(locale.LC_ALL, "")
            locale.setlocale(locale.LC_ALL, f"{lang_code}.UTF-8")
        except Exception:
            pass

    # Initialize gettext for C side (GTK/GLib)
    if hasattr(locale, 'bindtextdomain'):
        try:
            locale.bindtextdomain(domain, localedir)
            locale.textdomain(domain)
        except Exception:
            pass
    # The C components (like GLib/Gtk) will automatically pick up the LANGUAGE env var early on

# ALWAYS SETUP LANGUAGE FIRST, BEFORE IMPORTING GTK OR LIBADWAITA
_setup_language()

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from application import SentinelApplication  # noqa: E402
def main() -> int:
    """Launch the Sentinel application."""
    # Configure logging to show INFO and higher by default for development
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    logger = logging.getLogger("Sentinel")
    logger.info("Application starting...")

    # Initialize and attempt auto-unlock of local secure vault
    try:
        from services.vault_manager import VaultManager
        vm = VaultManager.get()
        if vm.startup():
            logger.info("Local vault: auto-unlocked via keyring.")
        else:
            logger.info("Local vault: manual unlock required (will prompt in UI).")
    except Exception as _ve:
        logger.warning("Local vault startup failed: %s", _ve)

    app = SentinelApplication()
    ret = app.run(sys.argv)

    try:
        from services.rclone_service import RcloneService
        RcloneService.get().unmount_all()
    except Exception as e:
        logging.error(f"Failed to unmount active FUSE directories: {e}")

    return ret


if __name__ == "__main__":
    sys.exit(main())
