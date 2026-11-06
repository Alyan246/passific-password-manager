"""Cryptographic primitives: Argon2id key derivation + AES-256-GCM.

On-disk blob layout (all integers big-endian):

    magic(4) | version(1) | time_cost(4) | memory_cost_KiB(4) | parallelism(1)
    | salt(16) | nonce(12) | ciphertext+tag

Everything up to and including the salt is the header. It is passed to
AES-GCM as associated data (AAD), so any tampering with the KDF parameters
or salt makes decryption fail.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PWMN"
FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16

_HEADER = struct.Struct(">4sBIIB")
HEADER_LEN = _HEADER.size + SALT_LEN


class VaultError(Exception):
    """Base class for all vault-related errors."""


class DecryptionError(VaultError):
    """Wrong master password, or the vault file is corrupted/tampered with."""


class FormatError(VaultError):
    """The file is not a valid pwman vault."""


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB (64 MiB)
    parallelism: int = 4

    def validate(self) -> None:
        # Bounds also protect against a crafted file that asks for absurd amounts of memory/time just by opening it.
        if not (1 <= self.time_cost <= 64):
            raise FormatError("KDF time_cost out of range")
        if not (1 <= self.parallelism <= 32):
            raise FormatError("KDF parallelism out of range")
        if not (8 * self.parallelism <= self.memory_cost <= 1 << 20):
            raise FormatError("KDF memory_cost out of range")


DEFAULT_PARAMS = KdfParams()


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def encrypt(password: str, plaintext: bytes, params: KdfParams | None = None) -> bytes:
    """Encrypt `plaintext` under a key derived from `password`.

    A fresh salt and nonce are generated on every call.
    """
    params = params or DEFAULT_PARAMS
    params.validate()
    salt = os.urandom(SALT_LEN)
    header = (
        _HEADER.pack(
            MAGIC,
            FORMAT_VERSION,
            params.time_cost,
            params.memory_cost,
            params.parallelism,
        )
        + salt
    )
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt, params)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    return header + nonce + ciphertext


def decrypt(password: str, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN + NONCE_LEN + TAG_LEN:
        raise FormatError("file is too short to be a pwman vault")

    magic, version, time_cost, memory_cost, parallelism = _HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise FormatError("not a pwman vault (bad magic bytes)")
    if version != FORMAT_VERSION:
        raise FormatError(f"unsupported vault format version {version}")

    params = KdfParams(time_cost, memory_cost, parallelism)
    params.validate()

    header = blob[:HEADER_LEN]
    salt = header[_HEADER.size :]
    nonce = blob[HEADER_LEN : HEADER_LEN + NONCE_LEN]
    ciphertext = blob[HEADER_LEN + NONCE_LEN :]

    key = derive_key(password, salt, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise DecryptionError(
            "wrong master password, or corrupted vault file"
        ) from None
