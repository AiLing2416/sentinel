# SPDX-License-Identifier: GPL-3.0-or-later

"""Data models for vault credentials and SSH key material."""

from __future__ import annotations

from dataclasses import dataclass

from utils.secure import SecureBytes


@dataclass
class VaultCredential:
    """A credential entry retrieved from the vault."""

    item_id: str
    name: str
    username: str | None = None
    has_password: bool = False
    has_ssh_key: bool = False
    has_totp: bool = False
    uri: str | None = None  # hostname / URL stored in the vault entry
    note: str | None = None # Additional info like "From Notes" or "Attachment"

    def __repr__(self) -> str:
        # Never expose actual credential values in repr
        return (
            f"VaultCredential(id={self.item_id!r}, name={self.name!r}, "
            f"user={self.username!r}, ssh_key={self.has_ssh_key})"
        )


@dataclass
class SSHKeyMaterial:
    """SSH key data retrieved from the vault.

    Contains SecureBytes that automatically zero memory on garbage collection.
    """

    private_key_pem: SecureBytes
    passphrase: SecureBytes | None = None
    key_type: str = "unknown"  # ed25519, rsa, ecdsa
    comment: str = ""

    def __repr__(self) -> str:
        # NEVER expose key material in repr
        return f"SSHKeyMaterial(type={self.key_type!r}, comment={self.comment!r})"
