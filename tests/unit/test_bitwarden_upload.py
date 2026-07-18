# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from vault.bitwarden import BitwardenBackend

def test_upload_ssh_key_create_new():
    async def run_test():
        backend = BitwardenBackend()
        backend.is_unlocked = AsyncMock(return_value=True)
        
        mock_run_bw = AsyncMock()
        async def side_effect(args, input_str=None):
            if "list" in args and "items" in args:
                return "[]"
            elif "encode" in args:
                return "mocked_encoded_string"
            elif "create" in args and "item" in args:
                return json.dumps({"id": "new-item-123", "name": "test-key", "type": 5})
            return ""
            
        mock_run_bw.side_effect = side_effect
        backend._run_bw = mock_run_bw

        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        priv_key = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        item_id = await backend.upload_ssh_key(
            label="test-key",
            private_key=priv_pem,
            public_key=None,
            passphrase=None
        )

        assert item_id == "new-item-123"
        assert mock_run_bw.call_count >= 3

    asyncio.run(run_test())


def test_upload_ssh_key_edit_existing():
    async def run_test():
        backend = BitwardenBackend()
        backend.is_unlocked = AsyncMock(return_value=True)
        
        mock_run_bw = AsyncMock()
        async def side_effect(args, input_str=None):
            if "list" in args and "items" in args:
                return json.dumps([{"id": "existing-item-456", "type": 5, "name": "existing-key"}])
            elif "get" in args and "item" in args:
                return json.dumps({"id": "existing-item-456", "type": 5, "name": "existing-key", "sshKey": {}})
            elif "encode" in args:
                return "mocked_encoded_string"
            elif "edit" in args and "item" in args:
                return ""
            return ""
            
        mock_run_bw.side_effect = side_effect
        backend._run_bw = mock_run_bw

        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        priv_key = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        item_id = await backend.upload_ssh_key(
            label="existing-key",
            private_key=priv_pem,
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKg...",
            passphrase=None
        )

        assert item_id == "existing-item-456"
        assert mock_run_bw.call_count >= 4

    asyncio.run(run_test())
