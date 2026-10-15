# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for DNS name resolution error handling and reachability distinction."""

from __future__ import annotations

import asyncio
import errno
import socket
import unittest
from unittest.mock import AsyncMock, patch

from models.connection import AuthMethod, Connection
from services.ssh_service import (
    SSHService,
    _connect_with_watchdog,
    _probe_ssh_banner,
)


class TestDnsErrorHandling(unittest.IsolatedAsyncioTestCase):
    """Test suite for DNS resolution errors vs host reachability in SSHService."""

    async def test_probe_ssh_banner_catches_gaierror(self) -> None:
        """Verify _probe_ssh_banner flags socket.gaierror as name_resolution_failed."""
        with patch("asyncio.open_connection", side_effect=socket.gaierror(-2, "Name or service not known")):
            ok, reason = await _probe_ssh_banner("nonexistent.invalid", 22, timeout=1.0)
            self.assertFalse(ok)
            self.assertTrue(reason.startswith("name_resolution_failed"))

    async def test_probe_ssh_banner_catches_os_error(self) -> None:
        """Verify _probe_ssh_banner flags generic OSError with os_error_."""
        with patch("asyncio.open_connection", side_effect=OSError(errno.EHOSTUNREACH, "No route to host")):
            ok, reason = await _probe_ssh_banner("192.0.2.1", 22, timeout=1.0)
            self.assertFalse(ok)
            self.assertTrue(reason.startswith("os_error"))

    async def test_watchdog_raises_gaierror_on_resolution_failure(self) -> None:
        """Verify _connect_with_watchdog re-raises socket.gaierror when probe flags resolution failure."""
        async def mock_connect():
            await asyncio.sleep(10)

        with patch("services.ssh_service._probe_ssh_banner", return_value=(False, "name_resolution_failed_-2")):
            with self.assertRaises(socket.gaierror):
                await _connect_with_watchdog(mock_connect(), "nonexistent.invalid", 22, fast_timeout=0.1)

    async def test_watchdog_raises_os_error_on_host_unreachable(self) -> None:
        """Verify _connect_with_watchdog re-raises OSError(EHOSTUNREACH) on network/host route failure."""
        async def mock_connect():
            await asyncio.sleep(10)

        with patch("services.ssh_service._probe_ssh_banner", return_value=(False, f"os_error_{errno.EHOSTUNREACH}")):
            with self.assertRaises(OSError) as ctx:
                await _connect_with_watchdog(mock_connect(), "192.0.2.1", 22, fast_timeout=0.1)
            self.assertEqual(ctx.exception.errno, errno.EHOSTUNREACH)

    async def test_establish_connection_reports_dns_error(self) -> None:
        """Verify _establish_connection passes 'Could not resolve hostname' on socket.gaierror."""
        service = SSHService()
        conn = Connection(
            id="test-conn",
            name="Test",
            hostname="nonexistent.invalid",
            port=22,
            username="user",
            auth_method=AuthMethod.PASSWORD,
        )

        reported_errors: list[str] = []
        cbs = {
            "ask_password": AsyncMock(return_value=None),
            "ask_host_key": AsyncMock(return_value=True),
            "on_error": lambda err: reported_errors.append(err),
        }

        # Mock VaultManager cached password so we bypass password prompting
        with patch("services.vault_manager.VaultManager.get") as mock_vm_get:
            mock_vm = mock_vm_get.return_value
            from utils.secure import SecureBytes
            mock_vm.get_cached_password.return_value = SecureBytes(b"secret")

            async def mock_watchdog_dns(coro, *args, **kwargs):
                try: coro.close()
                except Exception: pass
                raise socket.gaierror(-2, "Name or service not known")

            with patch("services.ssh_service.call_ui_sync", side_effect=lambda f, *args: f(*args)):
                with patch("services.ssh_service._connect_with_watchdog", side_effect=mock_watchdog_dns):
                    res = await service._establish_connection(conn, cbs)
                    self.assertIsNone(res)
                    self.assertEqual(len(reported_errors), 1)
                    # Translated or English "Could not resolve hostname"
                    self.assertIn(reported_errors[0], ["Could not resolve hostname", "无法解析主机名", "無法解析主機名稱"])

    async def test_establish_connection_reports_host_unreachable(self) -> None:
        """Verify _establish_connection passes 'Host unreachable' on EHOSTUNREACH."""
        service = SSHService()
        conn = Connection(
            id="test-conn-2",
            name="Test 2",
            hostname="192.0.2.1",
            port=22,
            username="user",
            auth_method=AuthMethod.PASSWORD,
        )

        reported_errors: list[str] = []
        cbs = {
            "ask_password": AsyncMock(return_value=None),
            "ask_host_key": AsyncMock(return_value=True),
            "on_error": lambda err: reported_errors.append(err),
        }

        with patch("services.vault_manager.VaultManager.get") as mock_vm_get:
            mock_vm = mock_vm_get.return_value
            from utils.secure import SecureBytes
            mock_vm.get_cached_password.return_value = SecureBytes(b"secret")

            async def mock_watchdog_unreach(coro, *args, **kwargs):
                try: coro.close()
                except Exception: pass
                raise OSError(errno.EHOSTUNREACH, "No route to host")

            with patch("services.ssh_service.call_ui_sync", side_effect=lambda f, *args: f(*args)):
                with patch("services.ssh_service._connect_with_watchdog", side_effect=mock_watchdog_unreach):
                    res = await service._establish_connection(conn, cbs)
                    self.assertIsNone(res)
                    self.assertEqual(len(reported_errors), 1)
                    self.assertIn(reported_errors[0], ["Host unreachable", "主机不可达", "主機無法連線"])

    async def test_end_to_end_resolution_failure(self) -> None:
        """End-to-end integration: invalid hostname through full watchdog probe."""
        service = SSHService()
        conn = Connection(
            id="test-conn-invalid-domain",
            name="Test Invalid Domain",
            hostname="invalid-domain-12345-not-exist.test",
            port=22,
            username="user",
            auth_method=AuthMethod.PASSWORD,
        )

        reported_errors: list[str] = []
        cbs = {
            "ask_password": AsyncMock(return_value=None),
            "ask_host_key": AsyncMock(return_value=True),
            "on_error": lambda err: reported_errors.append(err),
        }

        with patch("services.vault_manager.VaultManager.get") as mock_vm_get:
            mock_vm = mock_vm_get.return_value
            from utils.secure import SecureBytes
            mock_vm.get_cached_password.return_value = SecureBytes(b"secret")

            with patch("services.ssh_service.call_ui_sync", side_effect=lambda f, *args: f(*args)):
                res = await service._establish_connection(conn, cbs)
                self.assertIsNone(res)
                self.assertEqual(len(reported_errors), 1)
                self.assertIn(reported_errors[0], ["Could not resolve hostname", "无法解析主机名", "無法解析主機名稱"])


if __name__ == "__main__":
    unittest.main()
