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

## Release Notes (v0.2.0)

- **Enhanced Security**: Implemented zero-string copy memory management for credentials.
- **Refactored Vault**: New binary packing for the local secure vault, removing JSON intermediate states.
- **Terminal Fixes**: Improved keyboard input handling and visual theme consistency.
- **Localization**: Added support for German, Simplified Chinese, and Traditional Chinese.
- **CI/CD**: Automatic Flatpak builds on every release.
