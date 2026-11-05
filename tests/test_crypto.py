import pytest

from pwman import crypto
from pwman.crypto import DecryptionError, FormatError, KdfParams

FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)


def test_roundtrip():
    blob = crypto.encrypt("hunter2-hunter2", b"secret data", FAST)
    assert crypto.decrypt("hunter2-hunter2", blob) == b"secret data"


def test_wrong_password():
    blob = crypto.encrypt("right-password", b"x", FAST)
    with pytest.raises(DecryptionError):
        crypto.decrypt("wrong-password", blob)


def test_fresh_salt_and_nonce_each_time():
    a = crypto.encrypt("pw-pw-pw-pw", b"same", FAST)
    b = crypto.encrypt("pw-pw-pw-pw", b"same", FAST)
    assert a != b


def test_tampered_ciphertext_detected():
    blob = bytearray(crypto.encrypt("pw-pw-pw-pw", b"payload", FAST))
    blob[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        crypto.decrypt("pw-pw-pw-pw", bytes(blob))


def test_tampered_header_detected():
    blob = bytearray(crypto.encrypt("pw-pw-pw-pw", b"payload", FAST))
    blob[crypto.HEADER_LEN - 1] ^= 0x01  # flip a salt byte
    with pytest.raises(DecryptionError):
        crypto.decrypt("pw-pw-pw-pw", bytes(blob))


def test_bad_magic_and_short_file():
    with pytest.raises(FormatError):
        crypto.decrypt("x", b"short")
    blob = bytearray(crypto.encrypt("pw-pw-pw-pw", b"p", FAST))
    blob[0:4] = b"NOPE"
    with pytest.raises(FormatError):
        crypto.decrypt("pw-pw-pw-pw", bytes(blob))


def test_absurd_kdf_params_rejected():
    blob = bytearray(crypto.encrypt("pw-pw-pw-pw", b"p", FAST))
    blob[9:13] = (1 << 30).to_bytes(4, "big")  # memory_cost field
    with pytest.raises(FormatError):
        crypto.decrypt("pw-pw-pw-pw", bytes(blob))
