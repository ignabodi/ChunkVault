"""
Tests for client.crypto
=======================
Covers:
  - Correct encrypt → decrypt round-trip
  - Chunk index AAD prevents cross-chunk ciphertext replay
  - Wrong key fails with InvalidTag
  - Minimum size guard on decrypt
  - Key derivation is deterministic (same inputs → same key)
  - Different chunk indices produce different derived keys
"""

import pytest

from client.crypto import (
    InvalidTag,
    decrypt_chunk,
    derive_chunk_key,
    encrypt_chunk,
    generate_file_key,
)


class TestGenerateFileKey:
    def test_length(self):
        key = generate_file_key()
        assert len(key) == 32

    def test_random(self):
        assert generate_file_key() != generate_file_key()


class TestDeriveChunkKey:
    def test_deterministic(self):
        file_key = generate_file_key()
        assert derive_chunk_key(file_key, 0) == derive_chunk_key(file_key, 0)

    def test_differs_per_chunk(self):
        file_key = generate_file_key()
        assert derive_chunk_key(file_key, 0) != derive_chunk_key(file_key, 1)

    def test_differs_per_file_key(self):
        k1, k2 = generate_file_key(), generate_file_key()
        assert derive_chunk_key(k1, 0) != derive_chunk_key(k2, 0)

    def test_output_length(self):
        assert len(derive_chunk_key(generate_file_key(), 42)) == 32


class TestEncryptDecrypt:
    def test_round_trip(self):
        key = generate_file_key()
        plaintext = b"Hello, ChunkVault!"
        blob = encrypt_chunk(key, 0, plaintext)
        recovered = decrypt_chunk(key, 0, blob)
        assert recovered == plaintext

    def test_large_chunk(self):
        key = generate_file_key()
        plaintext = bytes(range(256)) * 4096  # 1 MiB
        blob = encrypt_chunk(key, 7, plaintext)
        assert decrypt_chunk(key, 7, blob) == plaintext

    def test_empty_plaintext(self):
        key = generate_file_key()
        blob = encrypt_chunk(key, 0, b"")
        assert decrypt_chunk(key, 0, blob) == b""

    def test_random_nonce_produces_different_ciphertexts(self):
        key = generate_file_key()
        blob1 = encrypt_chunk(key, 0, b"same plaintext")
        blob2 = encrypt_chunk(key, 0, b"same plaintext")
        assert blob1 != blob2  # different nonces

    def test_wrong_key_raises(self):
        key = generate_file_key()
        blob = encrypt_chunk(key, 0, b"secret")
        with pytest.raises(InvalidTag):
            decrypt_chunk(generate_file_key(), 0, blob)

    def test_wrong_chunk_index_raises(self):
        """AAD mismatch must cause authentication failure."""
        key = generate_file_key()
        blob = encrypt_chunk(key, 0, b"data for chunk 0")
        with pytest.raises(InvalidTag):
            # Telling decrypt this is chunk 1 – AAD won't match
            decrypt_chunk(key, 1, blob)

    def test_tampered_ciphertext_raises(self):
        key = generate_file_key()
        blob = bytearray(encrypt_chunk(key, 0, b"important"))
        blob[15] ^= 0xFF  # flip bits in ciphertext body
        with pytest.raises(InvalidTag):
            decrypt_chunk(key, 0, bytes(blob))

    def test_too_short_blob_raises(self):
        key = generate_file_key()
        with pytest.raises(ValueError):
            decrypt_chunk(key, 0, b"\x00" * 5)

    def test_ciphertext_is_longer_than_plaintext(self):
        """Blob = 12 B nonce + ciphertext + 16 B tag."""
        key = generate_file_key()
        plaintext = b"x" * 100
        blob = encrypt_chunk(key, 0, plaintext)
        assert len(blob) == 12 + len(plaintext) + 16
