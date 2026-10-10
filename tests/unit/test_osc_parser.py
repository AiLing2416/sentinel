import base64
import sys

sys.path.insert(0, "src")

from utils.osc_parser import Osc52Parser


def _b64(text: str) -> bytes:
    return base64.b64encode(text.encode("utf-8"))


def _make(**kwargs):
    calls = []
    parser = Osc52Parser(lambda target, text: calls.append((target, text)), **kwargs)
    return parser, calls


def test_write_bel_terminated():
    parser, calls = _make()
    out = parser.feed(b"a\x1b]52;c;" + _b64("hello") + b"\x07b")
    assert out == b"ab"
    assert calls == [("c", "hello")]


def test_write_st_terminated():
    parser, calls = _make()
    out = parser.feed(b"\x1b]52;p;" + _b64("hi") + b"\x1b\\x")
    assert out == b"x"
    assert calls == [("p", "hi")]


def test_write_8bit_sequence():
    parser, calls = _make()
    out = parser.feed(b"\x9d52;c;" + _b64("eight") + b"\x9c!")
    assert out == b"!"
    assert calls == [("c", "eight")]


def test_query_is_ignored_and_stripped():
    parser, calls = _make()
    out = parser.feed(b"x\x1b]52;c;?\x07y")
    assert out == b"xy"
    assert calls == []


def test_query_with_empty_target_is_ignored():
    parser, calls = _make()
    out = parser.feed(b"\x1b]52;;?\x07")
    assert out == b""
    assert calls == []


def test_query_prefix_with_trailing_data_is_ignored():
    parser, calls = _make()
    parser.feed(b"\x1b]52;c;?" + _b64("x") + b"\x07")
    assert calls == []


def test_query_never_produces_reply_output():
    parser, _ = _make()
    out = parser.feed(b"\x1b]52;c;?\x07")
    assert b"52" not in out


def test_invalid_base64_is_rejected():
    parser, calls = _make()
    out = parser.feed(b"\x1b]52;c;!!not-base64!!\x07z")
    assert out == b"z"
    assert calls == []


def test_empty_payload_clears_clipboard():
    parser, calls = _make()
    parser.feed(b"\x1b]52;c;\x07")
    assert calls == [("c", "")]


def test_split_across_chunks():
    parser, calls = _make()
    payload = b"\x1b]52;c;" + _b64("split") + b"\x07"
    out = parser.feed(payload[:3]) + parser.feed(payload[3:10]) + parser.feed(payload[10:])
    assert out == b""
    assert calls == [("c", "split")]


def test_oversized_payload_discarded():
    parser, calls = _make(max_payload_size=16)
    out = parser.feed(b"\x1b]52;c;" + b"A" * 64)
    assert out == b""
    out = parser.feed(b"tail\x07")
    assert calls == []
    assert out == b"tail\x07"


def test_reset_clears_state():
    parser, calls = _make()
    parser.feed(b"\x1b]52;c;abc")
    parser.reset()
    assert parser.feed(b"plain") == b"plain"
    assert calls == []


def test_plain_data_passthrough():
    parser, calls = _make()
    assert parser.feed(b"hello \x1b[31mworld") == b"hello \x1b[31mworld"
    assert calls == []
