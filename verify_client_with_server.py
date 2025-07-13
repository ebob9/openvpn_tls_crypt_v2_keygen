#!/usr/bin/env python3
"""
Verify that a client key is valid for a given server key.
This tests the cryptographic relationship between the keys.
"""

import os
import sys
import base64
import struct
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
from typing import Tuple, Optional


def decode_pem_key(filename: str) -> Tuple[bytes, str]:
    """Decode a PEM-formatted key file"""
    with open(filename, 'rb') as f:
        content = f.read()

    if b"server key" in content:
        key_type = "server"
    elif b"client key" in content:
        key_type = "client"
    else:
        raise ValueError("Unknown key type")

    # Extract base64 content
    start = content.find(b"-----\n") + 6
    end = content.find(b"\n-----END")
    b64_content = content[start:end].replace(b'\n', b'')

    # Decode base64
    key_data = base64.b64decode(b64_content)

    return key_data, key_type


def verify_client_server_relationship(server_key_file: str, client_key_file: str) -> bool:
    """
    Verify that a client key was generated with the given server key.

    This works by:
    1. Extracting the wrapped client key (WKc) from the client key file
    2. Using the server key to verify the HMAC tag
    3. Decrypting the wrapped portion to recover the client key and metadata

    Returns:
        True if the client key is valid for the server key, False otherwise
    """
    print(f"Verifying client-server key relationship:")
    print(f"  Server key: {server_key_file}")
    print(f"  Client key: {client_key_file}")
    print("-" * 60)

    try:
        # Decode both keys
        server_data, server_type = decode_pem_key(server_key_file)
        client_data, client_type = decode_pem_key(client_key_file)

        if server_type != "server" or client_type != "client":
            print("Wrong key types")
            return False

        print(f"✓ Server key size: {len(server_data)} bytes")
        print(f"✓ Client key total size: {len(client_data)} bytes")

        # Extract keys from server key
        ke = server_data[0:32]  # Encryption key
        ka = server_data[64:96]  # Authentication key

        print(f"✓ Extracted Ke (encryption key): {len(ke)} bytes")
        print(f"✓ Extracted Ka (authentication key): {len(ka)} bytes")

        # Extract client key components
        if len(client_data) < 256:
            print("Client key too small")
            return False

        kc = client_data[0:256]  # Raw client key
        wkc = client_data[256:]  # Wrapped client key

        print(f"✓ Client key Kc: {len(kc)} bytes")
        print(f"✓ Wrapped key WKc: {len(wkc)} bytes")

        # Parse WKc structure: Tag || Ciphertext || Length
        if len(wkc) < 34:  # Minimum: 32 (tag) + 2 (length)
            print("WKc too small")
            return False

        tag = wkc[0:32]
        length_bytes = wkc[-2:]
        ciphertext = wkc[32:-2]

        # Parse length field
        wkc_length = struct.unpack('!H', length_bytes)[0]
        print(f"✓ WKc length field: {wkc_length} bytes")

        # Verify length matches
        if len(wkc) != wkc_length:
            print(f"WKc length mismatch: field says {wkc_length}, actual is {len(wkc)}")
            return False
        print("✓ WKc length field matches actual size")

        # Decrypt the ciphertext to get Kc || metadata
        # Use the tag's first 128 bits as IV
        iv = tag[:16]
        iv_int = int.from_bytes(iv, 'big')

        # Create AES-256-CTR cipher
        ctr = Counter.new(128, initial_value=iv_int)
        cipher = AES.new(ke, AES.MODE_CTR, counter=ctr)

        # Decrypt
        plaintext = cipher.decrypt(ciphertext)

        # The plaintext should be Kc || metadata
        if len(plaintext) < 256:
            print("Decrypted data too small")
            return False

        decrypted_kc = plaintext[0:256]
        metadata = plaintext[256:]

        print(f"✓ Decrypted client key: {len(decrypted_kc)} bytes")
        print(f"✓ Metadata: {len(metadata)} bytes")

        # Verify the decrypted Kc matches the original
        if decrypted_kc != kc:
            print("Decrypted client key doesn't match original")
            print(f"  Original Kc (first 8 bytes): {kc[:8].hex()}")
            print(f"  Decrypted Kc (first 8 bytes): {decrypted_kc[:8].hex()}")
            return False

        print("✓ Decrypted client key matches original!")

        # Parse metadata
        if metadata:
            metadata_type = metadata[0]
            if metadata_type == 0x01 and len(metadata) >= 9:
                timestamp = struct.unpack('!Q', metadata[1:9])[0]
                print(f"✓ Metadata type: TIMESTAMP (0x01)")
                print(f"  Timestamp value: {timestamp}")
            elif metadata_type == 0x00:
                print(f"✓ Metadata type: USER (0x00)")
                print(f"  User data: {metadata[1:].hex()}")
            else:
                print(f"✓ Metadata type: {metadata_type:#04x}")

        # Now verify the HMAC tag
        # Recreate the HMAC input: len || Kc || metadata
        h = hmac.new(ka, digestmod=hashlib.sha256)
        h.update(length_bytes)
        h.update(kc)
        h.update(metadata)
        computed_tag = h.digest()

        if computed_tag != tag:
            print("HMAC verification failed")
            print(f"  Expected tag (first 8 bytes): {tag[:8].hex()}")
            print(f"  Computed tag (first 8 bytes): {computed_tag[:8].hex()}")
            return False

        print("✓ HMAC verification successful!")

        print("\n" + "=" * 60)
        print("CLIENT KEY IS VALID FOR THIS SERVER KEY!")
        print("=" * 60)

        return True

    except Exception as e:
        print(f"Error during verification: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_key_generation_and_verification():
    """Test the entire key generation and verification process"""
    print("\n=== Testing Key Generation and Verification ===\n")

    from ovpn_tls_crypt_v2_generator import TLSCryptV2Generator

    # Generate a server and client key pair
    print("1. Generating test keys...")
    generator = TLSCryptV2Generator(
        server_seed=b"test-server-seed-123",
        client_seed=b"test-client-seed-456"
    )

    server_pem, client_pem = generator.generate_keys()

    # Save to files
    with open("test-server.key", "w") as f:
        f.write(server_pem)
    with open("test-client.key", "w") as f:
        f.write(client_pem)

    print("   Keys generated and saved\n")

    # Verify the relationship
    print("2. Verifying client-server relationship...")
    if verify_client_server_relationship("test-server.key", "test-client.key"):
        print("\nTest passed: Generated keys are cryptographically linked")
    else:
        print("\nTest failed: Keys are not properly linked")

    # Test with wrong server key
    print("\n3. Testing with wrong server key...")
    wrong_generator = TLSCryptV2Generator(
        server_seed=b"wrong-server-seed",
        client_seed=b"other-client-seed"
    )
    wrong_server_pem, _ = wrong_generator.generate_keys()

    with open("wrong-server.key", "w") as f:
        f.write(wrong_server_pem)

    print("\nVerifying client key with WRONG server key:")
    if not verify_client_server_relationship("wrong-server.key", "test-client.key"):
        print("\nTest passed: Wrong server key correctly rejected")
    else:
        print("\nTest failed: Wrong server key was accepted!")

    # Cleanup
    for f in ["test-server.key", "test-client.key", "wrong-server.key"]:
        try:
            os.unlink(f)
        except:
            pass


def main():
    """Main entry point"""
    if len(sys.argv) == 3:
        # Verify specific key files
        server_key = sys.argv[1]
        client_key = sys.argv[2]

        if not os.path.exists(server_key):
            print(f"Error: Server key file not found: {server_key}")
            sys.exit(1)
        if not os.path.exists(client_key):
            print(f"Error: Client key file not found: {client_key}")
            sys.exit(1)

        if verify_client_server_relationship(server_key, client_key):
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        # Run tests
        print("TLS-crypt-v2 Client-Server Key Verification Tool")
        print("=" * 60)
        print("\nUsage: {} <server.key> <client.key>".format(sys.argv[0]))
        print("\nRunning self-test...\n")

        test_key_generation_and_verification()


if __name__ == "__main__":
    main()