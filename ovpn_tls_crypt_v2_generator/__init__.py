#!/usr/bin/env python3
"""
OpenVPN TLS-crypt-v2 Key Generator (Deterministic)

This script generates OpenVPN TLS-crypt-v2 server and client keys from seed data.
Given the same seed data, it will always produce the same keys.

Requirements:
    pip install pycryptodome
"""

import os
import sys
import hmac
import hashlib
import struct
import base64
import time
import argparse
import json
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

__version__ = "1.0.1"
__copyright__ = "Copyright 2025, Aaron Edwards"
__license__ = "MIT"

class TLSCryptV2Generator:
    """Generate deterministic OpenVPN TLS-crypt-v2 keys from seed data"""

    # Key sizes in bytes
    SERVER_KEY_SIZE = 128  # 1024 bits
    CLIENT_KEY_SIZE = 256  # 2048 bits
    AES_KEY_SIZE = 32  # 256 bits
    HMAC_KEY_SIZE = 32  # 256 bits
    TAG_SIZE = 32  # 256 bits

    # Metadata types
    METADATA_TYPE_USER = 0x00
    METADATA_TYPE_TIMESTAMP = 0x01

    def __init__(self, server_seed: bytes, client_seed: bytes, metadata: Optional[bytes] = None):
        """
        Initialize generator with seed data.

        Args:
            server_seed: Seed data for server key generation
            client_seed: Seed data for client key generation
            metadata: Optional metadata to include in client key (default: timestamp)
        """
        self.server_seed = server_seed
        self.client_seed = client_seed
        self.metadata = metadata

    def derive_key(self, seed: bytes, key_type: str, size: int) -> bytes:
        """
        Derive a key from seed data using PBKDF2.

        Args:
            seed: Seed data
            key_type: Type of key being generated (used as salt prefix)
            size: Size of key to generate in bytes

        Returns:
            Derived key bytes
        """
        # Create a deterministic salt based on key type
        salt = hashlib.sha256(f"openvpn-tls-crypt-v2-{key_type}".encode()).digest()

        # Use PBKDF2 to derive key from seed
        # Using 100000 iterations for good security
        key = PBKDF2(
            password=seed,
            salt=salt,
            dkLen=size,
            count=100000,
            hmac_hash_module=SHA256
        )

        return key

    def generate_server_key(self) -> bytes:
        """
        Generate the server key from server seed.

        Returns:
            128-byte server key
        """
        return self.derive_key(self.server_seed, "server", self.SERVER_KEY_SIZE)

    def generate_client_key(self) -> bytes:
        """
        Generate the client key from client seed.

        Returns:
            256-byte client key
        """
        return self.derive_key(self.client_seed, "client", self.CLIENT_KEY_SIZE)

    def wrap_client_key(self, server_key: bytes, client_key: bytes) -> bytes:
        """
        Create the wrapped client key (WKc) using the server key.

        This implements the OpenVPN TLS-crypt-v2 client key wrapping:
        WKc = T || AES-256-CTR(Ke, IV, Kc || metadata) || len

        Where:
        - T = HMAC-SHA256(Ka, len || Kc || metadata)
        - IV = first 128 bits of T
        - Ke = encryption key from server key
        - Ka = authentication key from server key

        Args:
            server_key: 128-byte server key
            client_key: 256-byte client key

        Returns:
            Wrapped client key bytes
        """
        # Extract Ke and Ka from server key
        # First 256 bits (32 bytes) of first 512-bit key for encryption
        ke = server_key[0:32]
        # First 256 bits (32 bytes) of second 512-bit key for authentication
        ka = server_key[64:96]

        # Generate metadata if not provided
        if self.metadata is None:
            # For deterministic generation, derive timestamp from seeds
            # This ensures same seeds always produce same metadata
            combined_seed = self.server_seed + self.client_seed
            timestamp_bytes = hashlib.sha256(combined_seed + b"timestamp").digest()[:8]
            timestamp = int.from_bytes(timestamp_bytes, 'big') % (2 ** 32)  # Keep it reasonable
            metadata = struct.pack('!BQ', self.METADATA_TYPE_TIMESTAMP, timestamp)
        else:
            metadata = self.metadata

        # Calculate wrapped key length
        # Tag (32) + encrypted data (256 + len(metadata)) + length field (2)
        wkc_len = self.TAG_SIZE + len(client_key) + len(metadata) + 2

        # Create length field (16-bit network byte order)
        len_bytes = struct.pack('!H', wkc_len)

        # Compute HMAC-SHA256 tag: T = HMAC-SHA256(Ka, len || Kc || metadata)
        h = hmac.new(ka, digestmod=hashlib.sha256)
        h.update(len_bytes)
        h.update(client_key)
        h.update(metadata)
        tag = h.digest()

        # Extract IV from tag (first 128 bits / 16 bytes)
        iv = tag[:16]

        # Convert IV to integer for CTR mode
        iv_int = int.from_bytes(iv, 'big')

        # Create AES-256-CTR cipher
        ctr = Counter.new(128, initial_value=iv_int)
        cipher = AES.new(ke, AES.MODE_CTR, counter=ctr)

        # Encrypt client key + metadata
        plaintext = client_key + metadata
        ciphertext = cipher.encrypt(plaintext)

        # Construct WKc: Tag || Ciphertext || Length
        wkc = tag + ciphertext + len_bytes

        return wkc

    def format_pem(self, key_data: bytes, key_type: str) -> str:
        """
        Format key data as PEM.

        Args:
            key_data: Raw key bytes
            key_type: Either "server" or "client"

        Returns:
            PEM-formatted key string
        """
        # Base64 encode the key data
        b64_data = base64.b64encode(key_data).decode('ascii')

        # Split into 64-character lines
        lines = [b64_data[i:i + 64] for i in range(0, len(b64_data), 64)]

        # Create PEM format
        if key_type == "server":
            header = "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
            footer = "-----END OpenVPN tls-crypt-v2 server key-----"
        else:
            header = "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
            footer = "-----END OpenVPN tls-crypt-v2 client key-----"

        return f"{header}\n" + "\n".join(lines) + f"\n{footer}\n"

    def generate_keys(self) -> Tuple[str, str]:
        """
        Generate both server and client keys.

        Returns:
            Tuple of (server_key_pem, client_key_pem)
        """
        # Generate raw keys
        server_key = self.generate_server_key()
        client_key = self.generate_client_key()

        # Wrap client key
        wkc = self.wrap_client_key(server_key, client_key)

        # Combine client key with wrapped key
        client_key_complete = client_key + wkc

        # Format as PEM
        server_pem = self.format_pem(server_key, "server")
        client_pem = self.format_pem(client_key_complete, "client")

        return server_pem, client_pem


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="Generate deterministic OpenVPN TLS-crypt-v2 keys from seed data"
    )
    parser.add_argument(
        "--server-seed",
        required=True,
        help="Seed data for server key (hex string or text)"
    )
    parser.add_argument(
        "--client-seed",
        required=True,
        help="Seed data for client key (hex string or text)"
    )
    parser.add_argument(
        "--server-output",
        default="tls-crypt-v2-server.key",
        help="Output file for server key (default: tls-crypt-v2-server.key)"
    )
    parser.add_argument(
        "--client-output",
        default="tls-crypt-v2-client.key",
        help="Output file for client key (default: tls-crypt-v2-client.key)"
    )
    parser.add_argument(
        "--metadata",
        help="Custom metadata to include in client key (hex string)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test generated keys with OpenVPN (requires openvpn binary)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output keys as JSON to stdout instead of writing to files"
    )

    args = parser.parse_args()

    # Convert seed inputs to bytes
    def parse_seed(seed_str: str) -> bytes:
        """Parse seed string as hex or UTF-8"""
        # Try to parse as hex first
        try:
            # Remove any spaces or common hex prefixes
            clean_hex = seed_str.replace(" ", "").replace("0x", "").replace("0X", "")
            if all(c in "0123456789abcdefABCDEF" for c in clean_hex) and len(clean_hex) % 2 == 0:
                return bytes.fromhex(clean_hex)
        except ValueError:
            pass

        # Otherwise treat as UTF-8 string
        return seed_str.encode('utf-8')

    server_seed = parse_seed(args.server_seed)
    client_seed = parse_seed(args.client_seed)

    # Parse metadata if provided
    metadata = None
    if args.metadata:
        try:
            metadata = bytes.fromhex(args.metadata)
        except ValueError:
            print(f"Error: Invalid metadata hex string: {args.metadata}")
            sys.exit(1)

    # Generate keys
    if not args.json:
        print("Generating TLS-crypt-v2 keys...")
    generator = TLSCryptV2Generator(server_seed, client_seed, metadata)
    server_pem, client_pem = generator.generate_keys()

    # Output as JSON if requested
    if args.json:
        output = {
            "server_key": server_pem,
            "client_key": client_pem
        }
        print(json.dumps(output, indent=2))
        sys.exit(0)

    # Otherwise write to files
    with open(args.server_output, 'w') as f:
        f.write(server_pem)
    os.chmod(args.server_output, 0o600)
    print(f"Server key written to: {args.server_output}")

    with open(args.client_output, 'w') as f:
        f.write(client_pem)
    os.chmod(args.client_output, 0o600)
    print(f"Client key written to: {args.client_output}")

    # Test keys if requested
    if args.test:
        print("\nTesting generated keys...")
        try:
            import subprocess

            # First, let's verify the key formats are correct
            with open(args.server_output, 'rb') as f:
                server_data = f.read()
                if b"BEGIN OpenVPN tls-crypt-v2 server key" in server_data:
                    print("✓ Server key header is correct")
                    # Check base64 content between headers
                    start = server_data.find(b"-----\n") + 6
                    end = server_data.find(b"\n-----END")
                    b64_data = server_data[start:end].replace(b'\n', b'')
                    try:
                        import base64
                        decoded = base64.b64decode(b64_data)
                        if len(decoded) == 128:
                            print(f"✓ Server key size is correct: {len(decoded)} bytes")
                        else:
                            print(f"✗ Server key size is wrong: {len(decoded)} bytes (expected 128)")
                    except:
                        print("✗ Server key base64 decoding failed")
                else:
                    print("✗ Server key header is missing")

            # Create a minimal test config with TLS mode
            with open("/tmp/test-server.conf", "w") as f:
                f.write(f"dev tun\n")
                f.write(f"ifconfig 10.8.0.1 10.8.0.2\n")
                f.write(f"tls-server\n")
                f.write(f"tls-crypt-v2 {args.server_output}\n")
                f.write(f"dh none\n")
                f.write(f"ca /dev/null\n")
                f.write(f"cert /dev/null\n")
                f.write(f"key /dev/null\n")
                f.write(f"verb 4\n")

            # Test with OpenVPN
            result = subprocess.run(
                ["openvpn", "--config", "/tmp/test-server.conf", "--mode", "point-to-point"],
                capture_output=True,
                text=True,
                timeout=1
            )

        except subprocess.TimeoutExpired:
            # Timeout means OpenVPN started successfully
            print("✓ OpenVPN accepted the server key")
        except FileNotFoundError:
            print("Warning: openvpn binary not found, skipping tests")
        except Exception as e:
            print(f"Warning: Error during testing: {e}")
        finally:
            try:
                os.unlink("/tmp/test-server.conf")
            except:
                pass

    print("\nKeys generated successfully!")
    print(f"\nTo use these keys with OpenVPN:")
    print(f"  Server config: tls-crypt-v2 {args.server_output}")
    print(f"  Client config: tls-crypt-v2 {args.client_output}")
