import getpass

import pytest

from pwman import cli, crypto
from pwman.crypto import KdfParams

MASTER = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(
        crypto, "DEFAULT_PARAMS", KdfParams(time_cost=1, memory_cost=64, parallelism=1)
    )


@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "vault.enc")


def feed(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(it))


def run(vault_path, *argv):
    return cli.main(["--vault", vault_path, *argv])


def test_full_flow(monkeypatch, vault_path, capsys):
    feed(monkeypatch, MASTER, MASTER)
    assert run(vault_path, "init") == 0

    feed(monkeypatch, MASTER, "pw-for-email", "pw-for-email")
    assert run(vault_path, "add", "email", "-u", "me@example.com") == 0

    feed(monkeypatch, MASTER)
    assert run(vault_path, "list") == 0
    assert "email" in capsys.readouterr().out

    feed(monkeypatch, MASTER)
    run(vault_path, "get", "email")
    out = capsys.readouterr().out
    assert "pw-for-email" not in out

    feed(monkeypatch, MASTER)
    run(vault_path, "get", "email", "--show")
    assert "pw-for-email" in capsys.readouterr().out

    feed(monkeypatch, MASTER)
    assert run(vault_path, "rm", "email", "-y") == 0


def test_generate_flag(monkeypatch, vault_path, capsys):
    feed(monkeypatch, MASTER, MASTER)
    run(vault_path, "init")
    feed(monkeypatch, MASTER)
    assert run(vault_path, "add", "gh", "-g", "-l", "24") == 0
    assert "Generated password:" in capsys.readouterr().out


def test_short_master_rejected(monkeypatch, vault_path, capsys):
    feed(monkeypatch, "short", "short")
    assert run(vault_path, "init") == 1
    assert "at least" in capsys.readouterr().err


def test_wrong_master_fails(monkeypatch, vault_path, capsys):
    feed(monkeypatch, MASTER, MASTER)
    run(vault_path, "init")
    feed(monkeypatch, "wrong wrong wrong")
    assert run(vault_path, "list") == 1
    assert "wrong master password" in capsys.readouterr().err


def test_missing_vault(vault_path, capsys):
    assert run(vault_path, "list") == 1
    assert "pwman init" in capsys.readouterr().err
