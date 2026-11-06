"""Vault data model and encrypted-file storage."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .crypto import FormatError, KdfParams, VaultError

SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entry:
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)


class Vault:
    """In-memory collection of entries, keyed by name."""

    def __init__(self, entries: dict[str, Entry] | None = None) -> None:
        self.entries: dict[str, Entry] = entries or {}

    def names(self) -> list[str]:
        return sorted(self.entries, key=str.lower)

    def search(self, query: str) -> list[str]:
        """Names of entries whose name, username or url contains `query`."""
        q = query.strip().lower()
        if not q:
            return self.names()
        return [
            n
            for n in self.names()
            if q in n.lower()
            or q in self.entries[n].username.lower()
            or q in self.entries[n].url.lower()
        ]

    def get(self, name: str) -> Entry:
        try:
            return self.entries[name]
        except KeyError:
            raise VaultError(f"no entry named {name!r}") from None

    def add(
        self,
        name: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        overwrite: bool = False,
    ) -> Entry:
        if not name.strip():
            raise VaultError("entry name cannot be empty")
        existing = self.entries.get(name)
        if existing and not overwrite:
            raise VaultError(f"entry {name!r} already exists (use --force to overwrite)")
        entry = Entry(username=username, password=password, url=url, notes=notes)
        if existing:
            entry.created = existing.created
        self.entries[name] = entry
        return entry

    def remove(self, name: str) -> None:
        if name not in self.entries:
            raise VaultError(f"no entry named {name!r}")
        del self.entries[name]

    def to_bytes(self) -> bytes:
        doc = {
            "schema": SCHEMA_VERSION,
            "entries": {k: asdict(v) for k, v in self.entries.items()},
        }
        return json.dumps(doc, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Vault":
        try:
            doc = json.loads(data)
            if doc["schema"] != SCHEMA_VERSION:
                raise FormatError(f"unsupported vault schema {doc['schema']}")
            entries = {k: Entry(**v) for k, v in doc["entries"].items()}
        except (ValueError, KeyError, TypeError) as exc:
            raise FormatError("vault contents are malformed") from exc
        return cls(entries)


# storage


def default_vault_path() -> Path:
    env = os.environ.get("PWMAN_VAULT")
    if env:
        return Path(env).expanduser()
    data_home = os.environ.get("XDG_DATA_HOME")
    base = Path(data_home) if data_home else Path.home() / ".local" / "share"
    return base / "pwman" / "vault.enc"


def _atomic_write(path: Path, data: bytes) -> None:
    """Write `data` to `path` atomically, with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mkstemp creates the file with mode 0600.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def save_vault(
    path: Path, master_password: str, vault: Vault, params: KdfParams | None = None
) -> None:
    blob = crypto.encrypt(master_password, vault.to_bytes(), params)
    _atomic_write(path, blob)


def load_vault(path: Path, master_password: str) -> Vault:
    blob = path.read_bytes()
    return Vault.from_bytes(crypto.decrypt(master_password, blob))


def create_vault(
    path: Path, master_password: str, params: KdfParams | None = None
) -> Vault:
    if path.exists():
        raise VaultError(f"a vault already exists at {path}")
    vault = Vault()
    save_vault(path, master_password, vault, params)
    return vault
