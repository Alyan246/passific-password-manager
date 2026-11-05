"""Cryptographically secure password generation."""

from __future__ import annotations

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
MIN_LENGTH = 8


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Generate a random password containing every selected character class."""
    if length < MIN_LENGTH:
        raise ValueError(f"length must be at least {MIN_LENGTH}")

    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append(SYMBOLS)

    alphabet = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
