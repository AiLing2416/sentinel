# SPDX-License-Identifier: GPL-3.0-or-later

"""Streaming parser for OSC (Operating System Command) escape sequences, notably OSC 52 (Clipboard)."""

from __future__ import annotations

import base64
import logging
from typing import Callable

logger = logging.getLogger(__name__)

# Max allowed clipboard payload in bytes (10 MB safeguard against DOS/memory abuse)
MAX_OSC52_PAYLOAD_SIZE = 10 * 1024 * 1024


class Osc52Parser:
    """A streaming parser for ANSI OSC 52 (Clipboard Integration) escape sequences.

    OSC 52 sequence formats:
      - 7-bit: ESC ] 52 ; <target> ; <data> [BEL | ESC \\]
      - 8-bit: OSC 52 ; <target> ; <data> [BEL | ST]

    This parser extracts the target ('c' for clipboard, 'p' for primary, etc.)
    and base64-decoded content, invokes `on_clipboard(target, text)`, and returns
    a sanitized byte stream free of OSC 52 escape sequences so the terminal emulator
    does not choke on unhandled sequences.
    """

    def __init__(
        self,
        on_clipboard: Callable[[str, str], None],
        max_payload_size: int = MAX_OSC52_PAYLOAD_SIZE,
    ) -> None:
        self.on_clipboard = on_clipboard
        self.max_payload_size = max_payload_size
        self._in_osc52 = False
        self._osc52_buf = bytearray()
        self._prefix_buf = bytearray()

    def reset(self) -> None:
        """Reset internal parsing buffers and state."""
        self._in_osc52 = False
        self._osc52_buf.clear()
        self._prefix_buf.clear()

    def feed(self, data: bytes) -> bytes:
        """Process an incoming chunk of bytes from the SSH/local channel.

        Returns:
            Clean bytes with OSC 52 sequences stripped out, safe to feed to VTE.
        """
        if not data:
            return b""

        # Prepend any partial prefix held from the previous chunk
        if self._prefix_buf:
            data = bytes(self._prefix_buf) + data
            self._prefix_buf.clear()

        out = bytearray()
        i = 0
        n = len(data)

        while i < n:
            if not self._in_osc52:
                # Look for the start of an OSC 52 sequence: "\x1b]52;" or "\x9d52;"
                esc_idx = data.find(b"\x1b]52;", i)
                osc_idx = data.find(b"\x9d52;", i)

                cands = [pos for pos in (esc_idx, osc_idx) if pos != -1]
                if not cands:
                    # Check if the end of data contains a partial prefix of "\x1b]52;"
                    tail = data[i:]
                    prefix_match = 0
                    target_prefix = b"\x1b]52;"
                    for length in range(min(len(tail), len(target_prefix) - 1), 0, -1):
                        if target_prefix.startswith(tail[-length:]):
                            prefix_match = length
                            break
                    if prefix_match > 0:
                        out.extend(tail[:-prefix_match])
                        self._prefix_buf.extend(tail[-prefix_match:])
                    else:
                        out.extend(tail)
                    break

                start_pos = min(cands)
                out.extend(data[i:start_pos])

                # Determine length of prefix: "\x1b]52;" is 5 bytes, "\x9d52;" is 4 bytes
                prefix_len = 5 if data[start_pos:start_pos + 2] == b"\x1b]" else 4
                i = start_pos + prefix_len
                self._in_osc52 = True
                self._osc52_buf.clear()
            else:
                # Currently inside OSC 52 sequence: search for terminators:
                # BEL (\x07), ST (\x1b\ or \x1b\x5c), or 8-bit ST (\x9c)
                bel_idx = data.find(b"\x07", i)
                st_idx = data.find(b"\x1b\x5c", i)
                st8_idx = data.find(b"\x9c", i)

                term_cands = []
                if bel_idx != -1:
                    term_cands.append((bel_idx, 1))
                if st_idx != -1:
                    term_cands.append((st_idx, 2))
                if st8_idx != -1:
                    term_cands.append((st8_idx, 1))

                if not term_cands:
                    # No terminator in this chunk; accumulate into buffer
                    self._osc52_buf.extend(data[i:])
                    if len(self._osc52_buf) > self.max_payload_size:
                        logger.warning("OSC 52 payload exceeded size limit (%d bytes), discarding", self.max_payload_size)
                        self._in_osc52 = False
                        self._osc52_buf.clear()
                    break

                term_cands.sort(key=lambda x: x[0])
                term_pos, term_len = term_cands[0]
                self._osc52_buf.extend(data[i:term_pos])
                i = term_pos + term_len
                self._in_osc52 = False

                self._process_osc52(bytes(self._osc52_buf))
                self._osc52_buf.clear()

        return bytes(out)

    def _process_osc52(self, payload: bytes) -> None:
        """Decode and handle a completed OSC 52 sequence payload."""
        try:
            # Format: <target>;<b64_data>
            parts = payload.split(b";", 1)
            if len(parts) == 2:
                target_bytes, b64_bytes = parts
            else:
                target_bytes, b64_bytes = b"c", parts[0]

            target = target_bytes.decode("ascii", errors="ignore").lower()
            if not target:
                target = "c"

            # Clean base64 bytes (remove whitespace/newlines if any)
            b64_clean = b"".join(b64_bytes.split())

            # Security: OSC 52 is write-only. Read/query requests ("?") are
            # dropped silently and never answered, so remote hosts cannot
            # read the local clipboard.
            if b64_clean.startswith(b"?"):
                logger.debug("OSC 52: Ignored query request for security")
                return

            if not b64_clean:
                # Empty payload: user wants to clear clipboard
                decoded_text = ""
            else:
                decoded_bytes = base64.b64decode(b64_clean, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")

            logger.debug("OSC 52: Received %d chars for target '%s'", len(decoded_text), target)
            self.on_clipboard(target, decoded_text)
        except Exception as e:
            logger.warning("Failed to decode OSC 52 payload: %s", e)
