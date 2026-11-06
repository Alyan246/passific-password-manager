import stat

import pytest

from pwman.crypto import DecryptionError, KdfParams, VaultError
from pwman.vault import Vault, create_vault, load_vault, save_vault

FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)
MASTER = "correct horse battery"


def test_create_save_load(tmp_path):
    path = tmp_path / "sub" / "vault.enc"
    create_vault(path, MASTER, FAST)
    v = load_vault(path, MASTER)
    v.add("github", "alyan", "s3cret", url="https://github.com")
    save_vault(path, MASTER, v, FAST)

    again = load_vault(path, MASTER)
    assert again.names() == ["github"]
    assert again.get("github").password == "s3cret"


def test_file_permissions_are_private(tmp_path):
    path = tmp_path / "vault.enc"
    create_vault(path, MASTER, FAST)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_no_plaintext_on_disk(tmp_path):
    path = tmp_path / "vault.enc"
    v = create_vault(path, MASTER, FAST)
    v.add("bank", "me", "UNIQUE-MARKER-123")
    save_vault(path, MASTER, v, FAST)
    raw = path.read_bytes()
    assert b"UNIQUE-MARKER-123" not in raw
    assert b"bank" not in raw


def test_wrong_master_password(tmp_path):
    path = tmp_path / "vault.enc"
    create_vault(path, MASTER, FAST)
    with pytest.raises(DecryptionError):
        load_vault(path, "not the password")


def test_create_refuses_to_overwrite(tmp_path):
    path = tmp_path / "vault.enc"
    create_vault(path, MASTER, FAST)
    with pytest.raises(VaultError):
        create_vault(path, MASTER, FAST)


def test_search():
    v = Vault()
    v.add("GitHub", "alyan", "x", url="https://github.com")
    v.add("email", "me@example.com", "x")
    assert v.search("") == ["email", "GitHub"]
    assert v.search("git") == ["GitHub"]
    assert v.search("EXAMPLE") == ["email"]
    assert v.search("nothing") == []


def test_duplicate_and_overwrite_and_remove():
    v = Vault()
    v.add("a", "u", "p1")
    with pytest.raises(VaultError):
        v.add("a", "u", "p2")
    created = v.get("a").created
    v.add("a", "u", "p2", overwrite=True)
    assert v.get("a").password == "p2"
    assert v.get("a").created == created
    v.remove("a")
    with pytest.raises(VaultError):
        v.get("a")
