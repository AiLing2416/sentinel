import asyncio
import time
import json
import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Mocking modules that might be missing or hard to setup
sys.modules["gi"] = MagicMock()
sys.modules["gi.repository"] = MagicMock()

from vault.bitwarden import BitwardenBackend
from utils.secure import SecureBytes

async def benchmark():
    backend = BitwardenBackend()
    backend._cli_path = "bw"
    backend._session_token = SecureBytes("fake-token")

    item_id = "fake-item-id"
    item_data = {
        "id": item_id,
        "name": "Test Item",
        "attachments": [
            {"id": "att1", "fileName": "other.txt"},
            {"id": "att2", "fileName": "id_rsa"},
            {"id": "att3", "fileName": "id_ed25519"},
            {"id": "att4", "fileName": "key.pem"},
        ]
    }

    async def mocked_run_bw(args, input_str=None):
        if args[0:2] == ["get", "item"]:
            return json.dumps(item_data)
        return ""

    async def mocked_run_bw_raw(args, input_str=None):
        if args[0:2] == ["get", "attachment"]:
            # Simulate network delay
            await asyncio.sleep(0.5)
            att_id = args[2]
            if att_id == "att4":
                return b"-----BEGIN OPENSSH PRIVATE KEY-----\n..."
            else:
                raise RuntimeError("Not this one")
        return b""

    with patch.object(BitwardenBackend, "is_unlocked", return_value=True), \
         patch.object(BitwardenBackend, "_run_bw", side_effect=mocked_run_bw), \
         patch.object(BitwardenBackend, "_run_bw_raw", side_effect=mocked_run_bw_raw):

        print("Starting benchmark...")
        start_time = time.perf_counter()
        key = await backend.get_ssh_key(item_id)
        end_time = time.perf_counter()

        print(f"Time taken: {end_time - start_time:.4f} seconds")
        print(f"Key found: {key is not None}")

if __name__ == "__main__":
    asyncio.run(benchmark())
