# SPDX-License-Identifier: GPL-3.0-or-later
import logging
import sys
import unittest
from pathlib import Path

# Add src to sys.path so we can import our modules
SRC_PATH = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(SRC_PATH))

from application import SentinelLogFilter


class TestLogFilter(unittest.TestCase):
    def setUp(self):
        self.filter = SentinelLogFilter()

    def test_ipv4_redaction(self):
        """Verify IPv4 addresses are redacted showing the first two octets."""
        text = "Connected to 192.168.1.100 on port 22"
        self.assertEqual(self.filter._redact(text), "Connected to 192.168.*.* on port 22")
        text2 = "Host 10.0.50.12 unreachable"
        self.assertEqual(self.filter._redact(text2), "Host 10.0.*.* unreachable")

    def test_ipv6_full_redaction(self):
        """Verify full 8-hextet IPv6 addresses are redacted."""
        text = "Connecting to 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        self.assertEqual(self.filter._redact(text), "Connecting to 2001:0db8:*:*")

    def test_ipv6_compressed_redaction(self):
        """Verify compressed IPv6 addresses (with ::) are redacted."""
        # 2 groups before ::
        text1 = "Connecting to 2001:db8::1"
        self.assertEqual(self.filter._redact(text1), "Connecting to 2001:db8:*:*")

        # More than 2 groups before ::
        text2 = "Connected to 2001:db8:85a3::8a2e:370:7334"
        self.assertEqual(self.filter._redact(text2), "Connected to 2001:db8:*:*")

        # 1 group before :: (e.g. link-local)
        text3 = "Connecting to fe80::1"
        self.assertEqual(self.filter._redact(text3), "Connecting to fe80:*:*")

        # Link-local with zone/scope ID
        text4 = "Connecting to fe80::1%eth0"
        self.assertEqual(self.filter._redact(text4), "Connecting to fe80:*:*")

        # Loopback and unspecified
        text5 = "Bound to ::1"
        self.assertEqual(self.filter._redact(text5), "Bound to ::*")
        text6 = "Default route ::"
        self.assertEqual(self.filter._redact(text6), "Default route ::*")

    def test_ipv6_ipv4_mapped(self):
        """Verify IPv4-mapped IPv6 addresses are redacted."""
        text = "IPv4 mapped address: ::ffff:192.168.1.1"
        self.assertEqual(self.filter._redact(text), "IPv4 mapped address: ::ffff:192.168.*.*")

    def test_ipv6_bracketed_and_punctuation(self):
        """Verify bracketed IPv6 and IPv6 followed by colon/punctuation are redacted."""
        text1 = "SSHService: Fast watchdog confirmed host [2001:db8::1]:22 is online"
        self.assertEqual(
            self.filter._redact(text1),
            "SSHService: Fast watchdog confirmed host [2001:db8:*:*]:22 is online",
        )

        text2 = "SSHService: Connection failed to 2001:0db8:85a3:0000:0000:8a2e:0370:7334: Timeout"
        self.assertEqual(
            self.filter._redact(text2),
            "SSHService: Connection failed to 2001:0db8:*:*: Timeout",
        )

        text3 = "Error connecting to [fe80::1%eth0]:22"
        self.assertEqual(self.filter._redact(text3), "Error connecting to [fe80:*:*]:22")

    def test_non_ip_tokens_not_mangled(self):
        """Ensure timestamps, MAC addresses, line numbers, and domains are not altered by IPv6 filter."""
        ts = "2026-10-19 22:23:29,123 [INFO] application started"
        self.assertEqual(self.filter._redact(ts), ts)

        mac = "Device MAC 00:1a:2b:3c:4d:5e registered"
        self.assertEqual(self.filter._redact(mac), mac)

        loc = "Error at src/application.py:123:45"
        self.assertEqual(self.filter._redact(loc), loc)

        port = "Listening on localhost:8080 and api.example.com:443"
        self.assertEqual(
            self.filter._redact(port),
            "Listening on localhost:8080 and ***.com:443",
        )

    def test_logging_filter_record(self):
        """Test logging.Filter integration on record.msg and record.args."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Connected to %s port %s",
            args=("2001:db8::1", 22),
            exc_info=None,
        )
        self.assertTrue(self.filter.filter(record))
        self.assertEqual(record.args, ("2001:db8:*:*", 22))

        record2 = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=11,
            msg="Failed to connect to 2001:db8:85a3::8a2e:370:7334",
            args=(),
            exc_info=None,
        )
        self.assertTrue(self.filter.filter(record2))
        self.assertEqual(record2.msg, "Failed to connect to 2001:db8:*:*")


if __name__ == "__main__":
    unittest.main()
