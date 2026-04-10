"""
ChunkVault Crypto
=================
Per-chunk AES-256-GCM encryption with HKDF key derivation.

Design
------
Each file has a 256-bit *master key*.  A unique *chunk key* is derived from
that master key and the chunk index using HKDF-SHA256, so:

  - chunk keys are independent (compromising one does not expose others)
  - random access is O(1): derive the key for chunk N, decrypt only that chunk

Wire format for a stored encrypted chunk:
  nonce (12 B) || AES-GCM ciphertext+tag (variable || 16 B)

The chunk index is bound to the ciphertext as Additional Authenticated Data
(AAD), which prevents an attacker from silently transplanting chunk N's
ciphertext into slot M.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
KEY_SIZE = 32   # AES-256
NONCE_SIZE = 12  # 96-bit nonce recommended for GCM
TAG_SIZE = 16   # GCM authentication tag
_HKDF_SALT = b"chunkvault-v1"


def generate_file_key() -> bytes:
    """Return a cryptographically random 256-bit file master key."""
    return os.urandom(KEY_SIZE)


def derive_chunk_key(file_key: bytes, chunk_index: int) -> bytes:
    """
    Derive a 256-bit AES key for *chunk_index* from *file_key* via HKDF-SHA256.

    Using a unique key per chunk ensures that even if one chunk's key leaks
    the remaining chunks stay protected.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=_HKDF_SALT,
        info=f"chunk-{chunk_index}".encode(),
    )
    return hkdf.derive(file_key)


def encrypt_chunk(file_key: bytes, chunk_index: int, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* for a specific chunk position using AES-256-GCM.

    Returns ``nonce || ciphertext+tag`` (the GCM tag is appended by the
    library inside *ciphertext*).

    The ``chunk_index`` is included as AAD so the ciphertext cannot be
    transplanted to a different slot without detection.
    """
    chunk_key = derive_chunk_key(file_key, chunk_index)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(chunk_key)
    aad = f"chunk-{chunk_index}".encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_chunk(file_key: bytes, chunk_index: int, encrypted: bytes) -> bytes:
    """
    Decrypt an encrypted chunk blob returned by :func:`encrypt_chunk`.

    Raises:
        ValueError: if the blob is too small to contain a valid header.
        cryptography.exceptions.InvalidTag: if the authentication tag check
            fails (data has been tampered with or the wrong key/index is used).
    """
    min_size = NONCE_SIZE + TAG_SIZE
    if len(encrypted) < min_size:
        raise ValueError(
            f"Encrypted chunk is {len(encrypted)} B, minimum is {min_size} B"
        )

    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    chunk_key = derive_chunk_key(file_key, chunk_index)
    aesgcm = AESGCM(chunk_key)
    aad = f"chunk-{chunk_index}".encode()
    return aesgcm.decrypt(nonce, ciphertext, aad)


__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "generate_file_key",
    "derive_chunk_key",
    "encrypt_chunk",
    "decrypt_chunk",
    "InvalidTag",
]
