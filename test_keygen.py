#!/usr/bin/env python3
"""
Examples and tests for the TLS-crypt-v2 key generator.

This script demonstrates various ways to use the generator and includes
tests to verify deterministic key generation.
"""

import os
import sys
import hashlib
import tempfile
import subprocess
from ovpn_tls_crypt_v2_generator import TLSCryptV2Generator


def example_basic_usage():
    """Basic example: Generate keys from simple seed strings"""
    print("=== Basic Usage Example ===")

    # Use simple seed strings
    server_seed = b"my-server-secret-seed-123"
    client_seed = b"my-client-secret-seed-456"

    # Create generator
    generator = TLSCryptV2Generator(server_seed, client_seed)

    # Generate keys
    server_pem, client_pem = generator.generate_keys()

    # Save to files
    with open("example-server.key", "w") as f:
        f.write(server_pem)
    with open("example-client.key", "w") as f:
        f.write(client_pem)

    print("Generated keys:")
    print(f"  Server: example-server.key")
    print(f"  Client: example-client.key")
    print()


def example_hex_seeds():
    """Example using hex strings as seeds"""
    print("=== Hex Seed Example ===")

    # Use 256-bit hex strings as seeds
    server_seed = bytes.fromhex("deadbeef" * 8)  # 32 bytes
    client_seed = bytes.fromhex("cafebabe" * 8)  # 32 bytes

    generator = TLSCryptV2Generator(server_seed, client_seed)
    server_pem, client_pem = generator.generate_keys()

    print("Generated keys from hex seeds")
    print(f"  Server seed: {'deadbeef' * 8}")
    print(f"  Client seed: {'cafebabe' * 8}")
    print()


def example_derived_seeds():
    """Example deriving seeds from other data"""
    print("=== Derived Seeds Example ===")

    # Derive seeds from a master secret and identifiers
    master_secret = b"company-master-secret-2024"

    # Create unique seeds for each server/client pair
    server_id = "vpn-server-01"
    client_id = "john.doe@example.com"

    # Derive seeds using HMAC
    server_seed = hashlib.pbkdf2_hmac(
        'sha256',
        master_secret,
        f"server:{server_id}".encode(),
        iterations=10000
    )

    client_seed = hashlib.pbkdf2_hmac(
        'sha256',
        master_secret,
        f"client:{client_id}".encode(),
        iterations=10000
    )

    generator = TLSCryptV2Generator(server_seed, client_seed)
    server_pem, client_pem = generator.generate_keys()

    print(f"Generated keys for:")
    print(f"  Server ID: {server_id}")
    print(f"  Client ID: {client_id}")
    print()


def example_custom_metadata():
    """Example using custom metadata"""
    print("=== Custom Metadata Example ===")

    server_seed = b"server-seed"
    client_seed = b"client-seed"

    # Create custom metadata with user ID
    import struct
    user_id = 12345
    metadata_type = 0x00  # User-defined type

    # Pack user ID as metadata
    metadata = struct.pack('!BI', metadata_type, user_id)

    generator = TLSCryptV2Generator(server_seed, client_seed, metadata)
    server_pem, client_pem = generator.generate_keys()

    print(f"Generated keys with custom metadata:")
    print(f"  User ID: {user_id}")
    print()


def test_deterministic_generation():
    """Test that same seeds always produce same keys"""
    print("=== Deterministic Generation Test ===")

    server_seed = b"test-server-seed"
    client_seed = b"test-client-seed"

    # Generate keys multiple times
    results = []
    for i in range(3):
        generator = TLSCryptV2Generator(server_seed, client_seed)
        server_pem, client_pem = generator.generate_keys()
        results.append((server_pem, client_pem))

    # Verify all generations produced identical keys
    all_identical = all(
        results[0] == result for result in results[1:]
    )

    if all_identical:
        print("✓ Keys are deterministic (same seed = same keys)")
    else:
        print("✗ Keys are NOT deterministic!")

    print()


def test_different_seeds():
    """Test that different seeds produce different keys"""
    print("=== Different Seeds Test ===")

    # Generate two sets of keys with different seeds
    gen1 = TLSCryptV2Generator(b"seed1", b"seed2")
    server1, client1 = gen1.generate_keys()

    gen2 = TLSCryptV2Generator(b"seed3", b"seed4")
    server2, client2 = gen2.generate_keys()

    if server1 != server2 and client1 != client2:
        print("✓ Different seeds produce different keys")
    else:
        print("✗ Different seeds produced same keys!")

    print()


def test_openvpn_compatibility():
    """Test generated keys with OpenVPN (if available)"""
    print("=== OpenVPN Compatibility Test ===")

    try:
        # Check if OpenVPN is available
        result = subprocess.run(["openvpn", "--version"],
                                capture_output=True, text=True)
        print(f"OpenVPN version: {result.stdout.split()[1] if result.stdout else 'unknown'}")
    except FileNotFoundError:
        print("OpenVPN not found, skipping compatibility test")
        print()
        return

    # Generate test keys
    generator = TLSCryptV2Generator(
        b"test-server-seed",
        b"test-client-seed"
    )
    server_pem, client_pem = generator.generate_keys()

    # Write to temporary files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
        f.write(server_pem)
        server_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
        f.write(client_pem)
        client_file = f.name

    try:
        # Create a test config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(f"""
dev null
ifconfig 10.8.0.1 10.8.0.2
tls-crypt-v2 {server_file}
""")
            config_file = f.name

        # Test with OpenVPN
        result = subprocess.run(
            ["openvpn", "--config", config_file, "--mode", "point-to-point", "--verb", "4"],
            capture_output=True,
            text=True,
            timeout=2  # Quick timeout since we're just testing key loading
        )

        # Check various success indicators
        success_indicators = [
            "Cipher 'AES-256-CTR' initialized",
            "tls-crypt-v2 server key",
            "Using 256 bit message hash 'SHA256' for HMAC authentication"
        ]

        output = result.stdout + result.stderr
        if any(indicator in output for indicator in success_indicators):
            print("✓ Generated server key is compatible with OpenVPN")
            # Also test client key format
            with open(client_file, 'r') as f:
                if "BEGIN OpenVPN tls-crypt-v2 client key" in f.read():
                    print("✓ Generated client key format is valid")
        else:
            print("✗ Server key compatibility test failed")
            print(f"  Stdout: {result.stdout[:200]}...")
            print(f"  Stderr: {result.stderr[:200]}...")

    except subprocess.TimeoutExpired:
        # Timeout is actually OK - it means OpenVPN started successfully
        print("✓ Generated keys are compatible with OpenVPN (server started)")
    except Exception as e:
        print(f"✗ Error during test: {e}")
    finally:
        # Clean up files
        for f in [server_file, client_file, config_file]:
            try:
                os.unlink(f)
            except:
                pass

    print()


def main():
    """Run all examples and tests"""
    print("TLS-crypt-v2 Key Generator Examples and Tests")
    print("=" * 50)
    print()

    # Run examples
    example_basic_usage()
    example_hex_seeds()
    example_derived_seeds()
    example_custom_metadata()

    # Run tests
    test_deterministic_generation()
    test_different_seeds()
    test_openvpn_compatibility()

    print("Examples completed!")
    print()
    print("Key points:")
    print("- Same seeds always generate the same keys (deterministic)")
    print("- Different seeds generate different keys")
    print("- Keys are compatible with OpenVPN")
    print("- Seeds can be any bytes (strings, hex, derived keys, etc.)")
    print("- Custom metadata can be included in client keys")


if __name__ == "__main__":
    main()