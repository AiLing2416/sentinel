# SPDX-License-Identifier: GPL-3.0-or-later

"""Connection data model with security-focused validation."""

from __future__ import annotations

import enum
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ── Enums ─────────────────────────────────────────────────────

class AuthMethod(enum.Enum):
    """SSH authentication methods."""
    PASSWORD = "password"
    KEY = "key"
    KEY_PASSPHRASE = "key_passphrase"
    AGENT = "agent"
    VAULT = "vault"


# ── Validation ────────────────────────────────────────────────

# Characters dangerous in shell contexts
_SHELL_META = re.compile(r'[;&|`$(){}[\]<>!\'\"\\\n\r\t]')

# Valid hostname: letters, digits, dots, hyphens (RFC 952 / 1123)
_HOSTNAME_RE = re.compile(
    r'^('
    r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r')$'
)

# Valid IPv4
_IPV4_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Simple IPv6 check (full & compressed forms)
_IPV6_RE = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')

# Path traversal patterns
_PATH_TRAVERSAL = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.IGNORECASE)


class ValidationError(ValueError):
    """Raised when model data fails validation."""


def validate_hostname(value: str) -> str:
    """Validate and return a safe hostname/IP address.

    Raises ValidationError for invalid or malicious hostnames.
    """
    if not value or not value.strip():
        raise ValidationError("Hostname cannot be empty")

    value = value.strip()

    if len(value) > 253:
        raise ValidationError(f"Hostname too long: {len(value)} chars (max 253)")

    if _SHELL_META.search(value):
        raise ValidationError(f"Hostname contains forbidden characters: {value!r}")

    if _PATH_TRAVERSAL.search(value):
        raise ValidationError(f"Hostname contains path traversal: {value!r}")

    # Accept valid hostnames, IPv4, or IPv6
    if _HOSTNAME_RE.match(value) or _IPV4_RE.match(value) or _IPV6_RE.match(value):
        return value

    raise ValidationError(f"Invalid hostname format: {value!r}")


def validate_port(value: int) -> int:
    """Validate SSH port number (1-65535)."""
    if not isinstance(value, int):
        raise ValidationError(f"Port must be an integer, got {type(value).__name__}")
    if value < 1 or value > 65535:
        raise ValidationError(f"Port out of range: {value} (must be 1-65535)")
    return value


def validate_username(value: str) -> str:
    """Validate SSH username — no shell metacharacters."""
    if not value:
        return value  # empty is allowed (will use system default)

    value = value.strip()

    if len(value) > 64:
        raise ValidationError(f"Username too long: {len(value)} chars (max 64)")

    if _SHELL_META.search(value):
        raise ValidationError(f"Username contains forbidden characters: {value!r}")

    if _PATH_TRAVERSAL.search(value):
        raise ValidationError(f"Username contains path traversal: {value!r}")

    return value


def validate_name(value: str) -> str:
    """Validate a display name — no path traversal."""
    if not value or not value.strip():
        raise ValidationError("Name cannot be empty")

    value = value.strip()

    if len(value) > 128:
        raise ValidationError(f"Name too long: {len(value)} chars (max 128)")

    if _PATH_TRAVERSAL.search(value):
        raise ValidationError(f"Name contains path traversal: {value!r}")

    return value


# ── Connection Model ──────────────────────────────────────────

@dataclass
class Connection:
    """SSH connection configuration.

    NOTE: This model intentionally has NO password/private-key fields.
    All sensitive credentials are managed by the vault subsystem.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    hostname: str = ""
    port: int = 22
    username: str = ""
    auth_method: AuthMethod = AuthMethod.KEY
    key_path: str | None = None
    vault_item_id: str | None = None
    jump_host_id: str | None = None
    group_id: str | None = None
    os_id: str | None = None
    notes: str = ""
    last_connected: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_forwarding: bool = False
    sort_order: int = 0

    def validate(self) -> None:
        """Validate all fields. Raises ValidationError on failure."""
        self.name = validate_name(self.name)
        self.hostname = validate_hostname(self.hostname)
        self.port = validate_port(self.port)
        self.username = validate_username(self.username)
        if self.jump_host_id and self.jump_host_id == self.id:
            raise ValidationError("A connection cannot be its own jump host.")

    def to_dict(self) -> dict:
        """Serialize to a dict suitable for database storage."""
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "auth_method": self.auth_method.value,
            "key_path": self.key_path,
            "vault_item_id": self.vault_item_id,
            "jump_host_id": self.jump_host_id,
            "group_id": self.group_id,
            "os_id": self.os_id,
            "notes": self.notes,
            "last_connected": self.last_connected.isoformat() if self.last_connected else None,
            "created_at": self.created_at.isoformat(),
            "agent_forwarding": int(self.agent_forwarding),
            "sort_order": self.sort_order,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Connection:
        """Deserialize from a database row dict."""
        return cls(
            id=data["id"],
            name=data["name"],
            hostname=data["hostname"],
            port=data["port"],
            username=data.get("username", ""),
            auth_method=AuthMethod(data.get("auth_method", "key")),
            key_path=data.get("key_path"),
            vault_item_id=data.get("vault_item_id"),
            jump_host_id=data.get("jump_host_id"),
            group_id=data.get("group_id"),
            os_id=data.get("os_id"),
            notes=data.get("notes", ""),
            last_connected=(
                datetime.fromisoformat(data["last_connected"])
                if data.get("last_connected")
                else None
            ),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(timezone.utc)
            ),
            agent_forwarding=bool(data.get("agent_forwarding", 0)),
            sort_order=data.get("sort_order", 0),
        )

    def __repr__(self) -> str:
        """Safe repr — never include sensitive fields."""
        return (
            f"Connection(id={self.id!r}, name={self.name!r}, "
            f"host={self.hostname}:{self.port}, user={self.username!r})"
        )
