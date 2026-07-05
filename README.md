# Sentinel

<p align="center">
  <img src="data/icons/hicolor/scalable/apps/io.github.ailing2416.sentinel.svg" width="128" height="128" alt="Sentinel Logo">
</p>

Sentinel is a native SSH connection manager designed specifically for the GNOME desktop environment. It provides a modern, secure, and deeply integrated terminal management solution.

## Core Features

- **SSH Session Management**: Supports multi-tab connections and integrated VTE terminal emulation.
- **Credential Integration**: Optional Bitwarden CLI integration for secure storage and retrieval of SSH keys and passwords.
- **Two-Factor Authentication (2FA)**: Automates TOTP verification code retrieval from Bitwarden.
- **Advanced Connectivity**: Supports multi-level jump hosts (ProxyJump) and SSH Agent Forwarding.
- **Port Forwarding**: Easy management of Local, Remote, and Dynamic (SOCKS) port forwarding rules.
- **SFTP Support**: Built-in file browsing and management via FUSE mounting.
- **Security First**: Sensitive data is encrypted in memory and never stored in plain text in the local database.

## Installation

You can download the latest Flatpak package from the GitHub Releases page.

### Command Line Installation

```bash
# Download and install the latest release
wget https://github.com/AiLing2416/sentinel/releases/latest/download/sentinel.flatpak -O /tmp/sentinel.flatpak
flatpak install --user /tmp/sentinel.flatpak
```

### Running the Application

```bash
flatpak run io.github.ailing2416.sentinel
```

## Architecture

Built with Python 3, PyGObject, and GTK4, following the GNOME Human Interface Guidelines (Adwaita). The project uses the Meson build system and supports Flatpak packaging.

## Release Notes (v0.3.0)

- **SSH Port Forwarding Management**: Complete management of Local, Remote, and Dynamic (SOCKS) port forwarding rules executing on dedicated background SSH channels. Added local port validation, default hostname fallbacks, and a redesigned card grid with a slide-out editor.
- **Enhanced Bitwarden Sync & Vault Settings**: Redesigned the Vault manager into a single-page Preferences layout. Replaced insecure local password caching with config sync via Bitwarden Secure Notes. Enforced pre-sync (`bw sync`) before data transfer and added an optional deletion sync workflow with a user confirmation dialog. Added payload compression and a usage progress indicator.
- **Security (Log Redactor)**: Introduced a smart log metadata redactor to automatically mask sensitive credentials, passwords, tokens, and host IPs in application logs.
- **Terminal CJK Character Support**: Fixed wide-character rendering alignment in VTE under Flatpak by bundling CJK fallback fonts. Corrected thin Latin glyph rendering issues.
- **UX & UI Layout Polishing**: Added a Tab context menu with *Duplicate Tab* actions and full multi-language support. Aligned host, port-forwarding, and keychain card grids to prevent stretching and layout shifts. Optimized entry rows placeholder font sizes to avoid clipping.
- **Multi-Arch & CI Pipeline**: Configured native AMD64 and ARM64 Flatpak builds on native runners. Fixed Flatpak permission flags, runtime installation issues, and Vte GObject namespace crashes in CI. Corrected internationalization (i18n) gettext initialization bugs.
