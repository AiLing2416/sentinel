# SPDX-License-Identifier: GPL-3.0-or-later

"""Concurrency unit tests for SecureVault."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
import pytest

from models.connection import AuthMethod, Connection
from utils.secure import SecureBytes
from vault.secure_vault import SecureVault


class TestSecureVaultConcurrency:
    """Test concurrent read/write operations on SecureVault to verify thread safety."""

    def test_concurrent_read_write(self, tmp_path: Path) -> None:
        db_path = tmp_path / "concurrent_vault.db"
        vault = SecureVault(path=db_path)
        vault.open()
        pwd = SecureBytes("MySecurePassword123!")
        vault.initialize(pwd)

        errors = []

        def writer_task(idx: int):
            try:
                conn = Connection(
                    id=f"conn_{idx}",
                    name=f"Server {idx}",
                    hostname=f"10.0.0.{idx}",
                    port=22,
                    username="user",
                    auth_method=AuthMethod.KEY,
                )
                vault.store_connection(conn)
                vault.store_password(f"pwd_{idx}", f"Pass {idx}", SecureBytes(f"secret_{idx}"))
            except Exception as e:
                errors.append(e)

        def reader_task(idx: int):
            try:
                vault.list_connections()
                vault.get_password(f"pwd_{idx}")
            except Exception as e:
                errors.append(e)

        # Run 20 concurrent threads doing read and write simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            write_futures = [executor.submit(writer_task, i) for i in range(20)]
            read_futures = [executor.submit(reader_task, i) for i in range(20)]
            concurrent.futures.wait(write_futures + read_futures)

        assert not errors, f"Concurrent operations encountered errors: {errors}"

        # Verify all records exist
        conns = vault.list_connections()
        assert len(conns) == 20
        vault.close()
