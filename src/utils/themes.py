# SPDX-License-Identifier: GPL-3.0-or-later

"""Terminal color themes."""

import json
import base64
import zlib
import gettext
from typing import TypedDict, List, Optional

_ = gettext.gettext

class ThemeDict(TypedDict):
    id: str
    name: str
    foreground: str
    background: str
    cursor: str
    highlight_fg: str
    highlight_bg: str
    palette: List[str]
    is_preset: Optional[bool]

PRESET_THEMES: List[ThemeDict] = [
    {
        "id": "mocha",
        "name": _("Catppuccin Mocha"),
        "is_preset": True,
        "foreground": "#cdd6f4",
        "background": "#1e1e2e",
        "cursor": "#f5e0dc",
        "highlight_fg": "#1e1e2e",
        "highlight_bg": "#f9e2af",
        "palette": [
            "#45475a", "#f38ba8", "#a6e3a1", "#f9e2af",
            "#89b4fa", "#f5c2e7", "#94e2d5", "#bac2de",
            "#585b70", "#f38ba8", "#a6e3a1", "#f9e2af",
            "#89b4fa", "#f5c2e7", "#94e2d5", "#a6adc8"
        ]
    },
    {
        "id": "nord",
        "name": _("Nord"),
        "is_preset": True,
        "foreground": "#d8dee9",
        "background": "#2e3440",
        "cursor": "#d8dee9",
        "highlight_fg": "#2e3440",
        "highlight_bg": "#88c0d0",
        "palette": [
            "#3b4252", "#bf616a", "#a3be8c", "#ebcb8b",
            "#81a1c1", "#b48ead", "#88c0d0", "#e5e9f0",
            "#4c566a", "#bf616a", "#a3be8c", "#ebcb8b",
            "#81a1c1", "#b48ead", "#8fbcbb", "#eceff4"
        ]
    },
    {
        "id": "solarized-dark",
        "name": _("Solarized Dark"),
        "is_preset": True,
        "foreground": "#839496",
        "background": "#002b36",
        "cursor": "#839496",
        "highlight_fg": "#002b36",
        "highlight_bg": "#b58900",
        "palette": [
            "#073642", "#dc322f", "#859900", "#b58900",
            "#268bd2", "#d33682", "#2aa198", "#eee8d5",
            "#002b36", "#cb4b16", "#586e75", "#657b83",
            "#839496", "#6c71c4", "#93a1a1", "#fdf6e3"
        ]
    },
    {
        "id": "dracula",
        "name": _("Dracula"),
        "is_preset": True,
        "foreground": "#f8f8f2",
        "background": "#282a36",
        "cursor": "#f8f8f2",
        "highlight_fg": "#282a36",
        "highlight_bg": "#f1fa8c",
        "palette": [
            "#21222c", "#ff5555", "#50fa7b", "#f1fa8c",
            "#bd93f9", "#ff79c6", "#8be9fd", "#f8f8f2",
            "#6272a4", "#ff6e6e", "#69ff94", "#ffffa5",
            "#d6acff", "#ff92df", "#a4ffff", "#ffffff"
        ]
    },
    {
        "id": "gnome-dark",
        "name": _("GNOME Dark"),
        "is_preset": True,
        "foreground": "#ffffff",
        "background": "#1e1e1e",
        "cursor": "#ffffff",
        "highlight_fg": "#1e1e1e",
        "highlight_bg": "#3584e4",
        "palette": [
            "#171717", "#c01c28", "#26a269", "#a2734c",
            "#12488b", "#a347ba", "#2aa1b3", "#d0cfcc",
            "#5e5c64", "#f66151", "#33da7a", "#e9ad0c",
            "#2a7bde", "#c061cb", "#33c7de", "#ffffff"
        ]
    },
    {
        "id": "gnome-light",
        "name": _("GNOME Light"),
        "is_preset": True,
        "foreground": "#171717",
        "background": "#ffffff",
        "cursor": "#171717",
        "highlight_fg": "#ffffff",
        "highlight_bg": "#3584e4",
        "palette": [
            "#171717", "#c01c28", "#26a269", "#a2734c",
            "#12488b", "#a347ba", "#2aa1b3", "#d0cfcc",
            "#5e5c64", "#f66151", "#33da7a", "#e9ad0c",
            "#2a7bde", "#c061cb", "#33c7de", "#ffffff"
        ]
    }
]

DEFAULT_THEME = PRESET_THEMES[0]

def encode_theme(theme: ThemeDict) -> str:
    """Encode theme into a compact string code."""
    # We only encode data, not name/id/is_preset
    data = {
        "fg": theme["foreground"],
        "bg": theme["background"],
        "cu": theme["cursor"],
        "hfg": theme["highlight_fg"],
        "hbg": theme["highlight_bg"],
        "pa": theme["palette"]
    }
    json_data = json.dumps(data, separators=(',', ':'))
    compressed = zlib.compress(json_data.encode('utf-8'))
    b64 = base64.b64encode(compressed).decode('utf-8')
    return f"ST1:{b64}"

def decode_theme(code: str, name: str = "Imported Theme") -> Optional[ThemeDict]:
    """Decode theme from a string code."""
    if not code.startswith("ST1:"):
        return None
    
    try:
        b64 = code[4:]
        compressed = base64.b64decode(b64)
        json_data = zlib.decompress(compressed).decode('utf-8')
        data = json.loads(json_data)
        
        import uuid
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "foreground": data["fg"],
            "background": data["bg"],
            "cursor": data["cu"],
            "highlight_fg": data["hfg"],
            "highlight_bg": data["hbg"],
            "palette": data["pa"],
            "is_preset": False
        }
    except Exception:
        return None
