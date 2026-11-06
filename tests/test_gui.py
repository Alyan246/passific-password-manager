import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QMessageBox  # noqa: E402

from pwman import crypto  # noqa: E402
from pwman.crypto import KdfParams  # noqa: E402
from pwman.gui import MainWindow, make_app  # noqa: E402

MASTER = "correct horse battery"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(
        crypto, "DEFAULT_PARAMS", KdfParams(time_cost=1, memory_cost=64, parallelism=1)
    )


@pytest.fixture
def answer(monkeypatch):
    """Control the reply of confirmation dialogs: answer['v'] = Yes / No."""
    state = {"v": QMessageBox.StandardButton.Yes}
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: state["v"]))
    return state


@pytest.fixture
def win(tmp_path):
    make_app()
    w = MainWindow(tmp_path / "vault.enc")
    yield w
    w.vault = None  # skip the discard prompt on teardown
    w.close()


def create_and_unlock(w):
    w.master_edit.setText(MASTER)
    w.confirm_edit.setText(MASTER)
    w._submit_unlock()


def add(w, name, user="u", pw="pw"):
    w.new_entry(force=True)
    w.name_edit.setText(name)
    w.user_edit.setText(user)
    w.pw_edit.setText(pw)
    w.save()


def test_create_vault_then_unlock(win):
    assert win.creating
    create_and_unlock(win)
    assert win.path.exists()
    assert win.stack.currentIndex() == 1

    win.lock()
    assert not win.creating  # now an existing vault
    win.master_edit.setText(MASTER)
    win._submit_unlock()
    assert win.stack.currentIndex() == 1


def test_create_rejects_short_or_mismatched_master(win):
    win.master_edit.setText("short")
    win.confirm_edit.setText("short")
    win._submit_unlock()
    assert "at least" in win.unlock_error.text()
    assert not win.path.exists()

    win.master_edit.setText(MASTER)
    win.confirm_edit.setText(MASTER + "x")
    win._submit_unlock()
    assert "do not match" in win.unlock_error.text()


def test_wrong_master_shows_error(win):
    create_and_unlock(win)
    win.lock()
    win.master_edit.setText("definitely wrong pw")
    win._submit_unlock()
    assert win.stack.currentIndex() == 0
    assert "wrong master password" in win.unlock_error.text().lower()


def test_add_rename_delete(win, answer):
    create_and_unlock(win)
    add(win, "github", "alyan", "s3cret")
    assert win.vault.names() == ["github"]
    assert win.listw.count() == 1

    # rename keeps data and creation time
    created = win.vault.get("github").created
    win.name_edit.setText("gitlab")
    win.save()
    assert win.vault.names() == ["gitlab"]
    assert win.vault.get("gitlab").password == "s3cret"
    assert win.vault.get("gitlab").created == created

    # persisted to disk
    from pwman.vault import load_vault

    assert load_vault(win.path, MASTER).names() == ["gitlab"]

    win.delete()
    assert win.vault.names() == []
    assert win.current is None


def test_duplicate_name_rejected(win):
    create_and_unlock(win)
    add(win, "a")
    add(win, "b")
    win.listw.setCurrentRow(1)
    win.name_edit.setText("a")
    win.save()
    assert "already exists" in win.status.text()
    assert win.vault.names() == ["a", "b"]


def test_search_filters_list(win):
    create_and_unlock(win)
    add(win, "github")
    add(win, "email")
    win.search.setText("git")
    assert [win.listw.item(i).text() for i in range(win.listw.count())] == ["github"]


def test_unsaved_changes_prompt(win, answer):
    create_and_unlock(win)
    add(win, "a")
    add(win, "b")
    win.listw.setCurrentRow(0)
    assert win.current == "a"

    win.name_edit.setText("a-edited")
    answer["v"] = QMessageBox.StandardButton.No
    win.listw.setCurrentRow(1)  # try to leave
    assert win.current == "a"
    assert win.name_edit.text() == "a-edited"

    answer["v"] = QMessageBox.StandardButton.Yes
    win.listw.setCurrentRow(1)
    assert win.current == "b"


def test_lock_wipes_state(win):
    create_and_unlock(win)
    add(win, "a", pw="topsecret")
    win.lock(force=True)
    assert win.vault is None and win.master is None
    assert win.pw_edit.text() == ""
    assert win.listw.count() == 0


def test_clipboard_copy_and_clear(win):
    create_and_unlock(win)
    win.pw_edit.setText("clip-me-123")
    win.copy_password()
    clip = QGuiApplication.clipboard()
    assert clip.text() == "clip-me-123"
    win._clear_clipboard()
    assert clip.text() == ""
