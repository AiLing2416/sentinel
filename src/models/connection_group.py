# SPDX-License-Identifier: GPL-3.0-or-later

"""Connection group model."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from models.connection import ValidationError, validate_name


@dataclass
class ConnectionGroup:
    """A named group (folder) for organizing connections."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    parent_id: str | None = None
    sort_order: int = 0
    color: str | None = None  # accent color hex

    def validate(self) -> None:
        self.name = validate_name(self.name)
        if self.color and not self.color.startswith("#"):
            raise ValidationError(f"Color must be a hex string, got: {self.color!r}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "parent_id": self.parent_id,
            "sort_order": self.sort_order,
            "color": self.color,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ConnectionGroup:
        return cls(
            id=data["id"],
            name=data["name"],
            parent_id=data.get("parent_id"),
            sort_order=data.get("sort_order", 0),
            color=data.get("color"),
        )
