# SPDX-License-Identifier: GPL-3.0-or-later

"""Port forward rule model."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from models.connection import ValidationError, validate_port


class ForwardType(enum.Enum):
    LOCAL = "local"
    REMOTE = "remote"
    DYNAMIC = "dynamic"


@dataclass
class ForwardRule:
    """An SSH port forwarding rule attached to a connection."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    connection_id: str = ""
    type: ForwardType = ForwardType.LOCAL
    bind_address: str = "localhost"
    bind_port: int = 0
    remote_host: str | None = "localhost"
    remote_port: int | None = None
    enabled: bool = True
    auto_start: bool = False

    def validate(self) -> None:
        validate_port(self.bind_port)
        if self.type != ForwardType.DYNAMIC:
            if not self.remote_host:
                raise ValidationError("Remote host required for local/remote forwards")
            if self.remote_port is not None:
                validate_port(self.remote_port)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "connection_id": self.connection_id,
            "type": self.type.value,
            "bind_address": self.bind_address,
            "bind_port": self.bind_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "enabled": int(self.enabled),
            "auto_start": int(self.auto_start),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ForwardRule:
        return cls(
            id=data["id"],
            connection_id=data["connection_id"],
            type=ForwardType(data["type"]),
            bind_address=data.get("bind_address", "localhost"),
            bind_port=data["bind_port"],
            remote_host=data.get("remote_host", "localhost"),
            remote_port=data.get("remote_port"),
            enabled=bool(data.get("enabled", 1)),
            auto_start=bool(data.get("auto_start", 0)),
        )
