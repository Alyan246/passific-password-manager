import string

import pytest

from pwman.generator import SYMBOLS, generate_password


def test_length_and_classes():
    for _ in range(50):
        pw = generate_password(16)
        assert len(pw) == 16
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_no_symbols():
    for _ in range(50):
        assert not any(c in SYMBOLS for c in generate_password(20, symbols=False))


def test_too_short_rejected():
    with pytest.raises(ValueError):
        generate_password(4)


def test_not_constant():
    assert generate_password(24) != generate_password(24)
