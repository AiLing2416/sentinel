# SPDX-License-Identifier: GPL-3.0-or-later

"""SSH Key generation and formatting utilities using cryptography library."""

from __future__ import annotations

import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


def generate_key_pair(
    key_type: str, passphrase: str | None = None
) -> tuple[str, str, str]:
    """Generate a new SSH key pair.

    Args:
        key_type: "ED25519" or "RSA"
        passphrase: Optional string passphrase to encrypt the private key.

    Returns:
        A tuple of (private_key_pem, public_key_openssh, fingerprint)
    """
    if key_type.upper() == "ED25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type.upper() == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    # Configure encryption algorithm
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption_algorithm = serialization.NoEncryption()

    # Get private key PEM
    private_pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption_algorithm,
    )
    private_pem = private_pem_bytes.decode("utf-8")

    # Get public key OpenSSH format
    public_key = private_key.public_key()
    public_openssh_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    public_openssh = public_openssh_bytes.decode("utf-8")

    # Calculate fingerprint
    fingerprint = calculate_fingerprint(public_openssh)

    return private_pem, public_openssh, fingerprint


def calculate_fingerprint(public_openssh: str) -> str:
    """Calculate the SHA256 fingerprint of an OpenSSH public key."""
    try:
        parts = public_openssh.strip().split()
        if len(parts) >= 2:
            key_data = base64.b64decode(parts[1])
            sha256_hash = hashlib.sha256(key_data).digest()
            fp_base64 = base64.b64encode(sha256_hash).decode().rstrip("=")
            return f"SHA256:{fp_base64}"
    except Exception:
        pass
    return "unknown"


def extract_public_key_from_private(
    private_key_pem: str, passphrase: str | None = None
) -> tuple[str, str, str]:
    """Load private key PEM and return (public_key_openssh, fingerprint, key_type)."""
    password = passphrase.encode("utf-8") if passphrase else None
    
    # Try loading as SSH private key
    try:
        private_key = serialization.load_ssh_private_key(
            private_key_pem.encode("utf-8"),
            password=password
        )
    except Exception:
        # Try loading as standard PEM private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=password
            )
        except Exception as e2:
            raise ValueError(f"Failed to load private key: {e2}")
            
    public_key = private_key.public_key()
    public_openssh_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    public_openssh = public_openssh_bytes.decode("utf-8")
    
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        key_type = "ED25519"
    elif isinstance(private_key, rsa.RSAPrivateKey):
        key_type = f"RSA-{private_key.key_size}"
    else:
        key_type = "UNKNOWN"
        
    fingerprint = calculate_fingerprint(public_openssh)
    return public_openssh, fingerprint, key_type

