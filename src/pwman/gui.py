from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QGuiApplication, QKeySequence, QPalette, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .cli import MIN_MASTER_LEN
from .crypto import VaultError
from .generator import generate_password
from .vault import Vault, create_vault, default_vault_path, load_vault, save_vault

APP_NAME = "Passific"
CLIPBOARD_CLEAR_MS = 20_000
AUTO_LOCK_MS = 5 * 60_000
FONT_FAMILIES = ["Inter", "Carlito", "Calibri", "Noto Sans", "DejaVu Sans"]

BG = "#1a1a1b"
SIDEBAR = "#212123"
INPUT = "#242426"
INK = "#e6e6e6"
MUTED = "#9a9a9c"
BORDER = "#3a3a3d"
DIVIDER = "#2f2f32"
BUTTON = "#2d2d30"
BUTTON_HOVER = "#363639"
BUTTON_PRESSED = "#3e3e42"
ACCENT = "#56913d"
ACCENT_HOVER = "#398046"
ACCENT_PRESSED = "#558034"
FOCUS = "#7ec86f"
SELECTED = "#2e4734"
ERROR = "#e08080"

STYLE = f"""
* {{ color: {INK}; font-size: 13px; }}
QMainWindow, QDialog, QMessageBox, QWidget#page {{ background: {BG}; }}
QWidget#sidebar {{ background: {SIDEBAR}; border-right: 1px solid {DIVIDER}; }}

QLabel#muted {{ color: {MUTED}; font-size: 12px; }}
QLabel#title {{ font-size: 22px; font-weight: 600; }}
QLabel#heading {{ font-size: 16px; font-weight: 600; }}
QLabel#error {{ color: {ERROR}; }}

QLineEdit, QPlainTextEdit {{
    background: {INPUT}; border: 1px solid {BORDER}; border-radius: 2px;
    padding: 6px 8px; selection-background-color: #3a4f68; selection-color: {INK};
}}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 1px solid {FOCUS}; }}

QPushButton {{
    background: {BUTTON}; border: 1px solid {BORDER}; border-radius: 2px; padding: 6px 14px;
}}
QPushButton:hover {{ background: {BUTTON_HOVER}; }}
QPushButton:pressed {{ background: {BUTTON_PRESSED}; }}
QPushButton:disabled {{ color: #6a6a6d; background: {SIDEBAR}; }}
QPushButton#primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: #ffffff; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_PRESSED}; }}
QPushButton#danger {{ color: {ERROR}; }}
QPushButton#danger:disabled {{ color: #7a5a5a; }}

QListWidget {{ background: transparent; border: none; outline: 0; }}
QListWidget::item {{ padding: 8px 10px; }}
QListWidget::item:hover:!selected {{ background: {BUTTON}; }}
QListWidget::item:selected {{ background: {SELECTED}; color: {INK}; }}
"""

def _panel(name: str) -> QWidget:
    w = QWidget()
    w.setObjectName(name)
    w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    return w


def _label(text: str = "", name: str = "") -> QLabel:
    lab = QLabel(text)
    if name:
        lab.setObjectName(name)
    return lab


def _button(text: str, name: str = "") -> QPushButton:
    b = QPushButton(text)
    if name:
        b.setObjectName(name)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def _sentence(msg: str) -> str:
    return msg[:1].upper() + msg[1:]


class MainWindow(QMainWindow):
    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path
        self.master: str | None = None
        self.vault: Vault | None = None
        self.current: str | None = None 
        self.creating = False
        self._baseline: tuple[str, ...] = ("",) * 5
        self._copied: str | None = None

        self.setWindowTitle(APP_NAME)
        self.resize(880, 560)
        self.setMinimumSize(720, 460)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_unlock())
        self.stack.addWidget(self._build_main())
        self.setCentralWidget(self.stack)

        self.clip_timer = QTimer(self, singleShot=True, interval=CLIPBOARD_CLEAR_MS)
        self.clip_timer.timeout.connect(self._clear_clipboard)
        self.lock_timer = QTimer(self, singleShot=True, interval=AUTO_LOCK_MS)
        self.lock_timer.timeout.connect(lambda: self.lock(force=True))
        QApplication.instance().installEventFilter(self)
        QShortcut(QKeySequence("Ctrl+S"), self, activated=self.save)

        self.show_unlock()

    # unlock page

    def _build_unlock(self) -> QWidget:
        page = _panel("page")
        outer = QVBoxLayout(page)

        box = QWidget()
        box.setFixedWidth(320)
        col = QVBoxLayout(box)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(10)

        self.unlock_hint = _label(name="muted")
        self.unlock_hint.setWordWrap(True)
        self.master_edit = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.master_edit.setPlaceholderText("Master password")
        self.confirm_edit = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText("Confirm master password")
        self.unlock_error = _label(name="error")
        self.unlock_error.setWordWrap(True)
        self.unlock_btn = _button("Unlock", "primary")

        col.addWidget(_label(APP_NAME, "title"))
        col.addWidget(self.unlock_hint)
        col.addSpacing(6)
        col.addWidget(self.master_edit)
        col.addWidget(self.confirm_edit)
        col.addWidget(self.unlock_error)
        col.addWidget(self.unlock_btn)

        outer.addStretch(1)
        outer.addWidget(box, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(2)

        self.master_edit.returnPressed.connect(self._on_master_enter)
        self.confirm_edit.returnPressed.connect(self._submit_unlock)
        self.unlock_btn.clicked.connect(self._submit_unlock)
        return page

    def show_unlock(self) -> None:
        self.creating = not self.path.exists()
        self.confirm_edit.setVisible(self.creating)
        self.unlock_btn.setText("Create vault" if self.creating else "Unlock")
        if self.creating:
            self.unlock_hint.setText(
                f"No vault found at {self.path}. Choose a master password "
                f"of at least {MIN_MASTER_LEN} characters."
            )
        else:
            self.unlock_hint.setText(str(self.path))
        self.unlock_error.clear()
        self.stack.setCurrentIndex(0)
        self.master_edit.setFocus()

    def _on_master_enter(self) -> None:
        if self.creating:
            self.confirm_edit.setFocus()
        else:
            self._submit_unlock()

    def _submit_unlock(self) -> None:
        pw = self.master_edit.text()
        try:
            if self.creating:
                if pw != self.confirm_edit.text():
                    raise VaultError("passwords do not match")
                if len(pw) < MIN_MASTER_LEN:
                    raise VaultError(
                        f"master password must be at least {MIN_MASTER_LEN} characters"
                    )
                vault = create_vault(self.path, pw)
            else:
                vault = load_vault(self.path, pw)
        except (VaultError, OSError) as exc:
            self.unlock_error.setText(_sentence(str(exc)) + ".")
            self.master_edit.clear()
            self.confirm_edit.clear()
            self.master_edit.setFocus()
            return

        self.master, self.vault = pw, vault
        self.master_edit.clear()
        self.confirm_edit.clear()
        self.unlock_error.clear()
        self.search.clear()
        self.refresh_list()
        self._fill(None)
        self.stack.setCurrentIndex(1)
        self.lock_timer.start()
        self.name_edit.setFocus()

    # main page

    def _build_main(self) -> QWidget:
        page = _panel("page")
        root = QHBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Sidebar
        side = _panel("sidebar")
        side.setFixedWidth(250)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 12, 12, 12)
        sl.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search")
        self.listw = QListWidget()
        new_btn = _button("New entry")
        lock_btn = _button("Lock")
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(new_btn, 1)
        row.addWidget(lock_btn)
        sl.addWidget(self.search)
        sl.addWidget(self.listw, 1)
        sl.addLayout(row)

        # Form
        form = _panel("page")
        fl = QVBoxLayout(form)
        fl.setContentsMargins(28, 24, 28, 20)
        fl.setSpacing(4)

        self.heading = _label("New entry", "heading")
        self.name_edit = QLineEdit()
        self.user_edit = QLineEdit()
        self.url_edit = QLineEdit()
        self.pw_edit = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.notes_edit = QPlainTextEdit()
        self.show_btn = _button("Show")
    
        fm = self.show_btn.fontMetrics()
        self.show_btn.setFixedWidth(
            max(fm.horizontalAdvance("Show"), fm.horizontalAdvance("Hide")) + 34
        )
        copy_btn = _button("Copy")
        gen_btn = _button("Generate")

        pw_row = QHBoxLayout()
        pw_row.setSpacing(8)
        pw_row.addWidget(self.pw_edit, 1)
        pw_row.addWidget(self.show_btn)
        pw_row.addWidget(copy_btn)
        pw_row.addWidget(gen_btn)

        fl.addWidget(self.heading)
        fl.addSpacing(10)
        for text, widget in (("Name", self.name_edit), ("Username", self.user_edit), ("URL", self.url_edit)):
            fl.addWidget(_label(text, "muted"))
            fl.addWidget(widget)
            fl.addSpacing(8)
        fl.addWidget(_label("Password", "muted"))
        fl.addLayout(pw_row)
        fl.addSpacing(8)
        fl.addWidget(_label("Notes", "muted"))
        fl.addWidget(self.notes_edit, 1)
        fl.addSpacing(12)

        self.save_btn = _button("Save", "primary")
        self.delete_btn = _button("Delete", "danger")
        self.status = _label(name="muted")
        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        bottom.addWidget(self.save_btn)
        bottom.addWidget(self.delete_btn)
        bottom.addSpacing(8)
        bottom.addWidget(self.status, 1)
        fl.addLayout(bottom)

        root.addWidget(side)
        root.addWidget(form, 1)

        self.search.textChanged.connect(lambda _t: self.refresh_list())
        self.listw.currentItemChanged.connect(self._on_select)
        new_btn.clicked.connect(lambda: self.new_entry())
        lock_btn.clicked.connect(lambda: self.lock())
        self.show_btn.clicked.connect(self.toggle_show)
        copy_btn.clicked.connect(self.copy_password)
        gen_btn.clicked.connect(self.generate)
        self.save_btn.clicked.connect(self.save)
        self.delete_btn.clicked.connect(self.delete)
        return page

    # form helpers

    def _values(self) -> tuple[str, ...]:
        return (
            self.name_edit.text(),
            self.user_edit.text(),
            self.url_edit.text(),
            self.pw_edit.text(),
            self.notes_edit.toPlainText(),
        )

    def _is_dirty(self) -> bool:
        return self.vault is not None and self._values() != self._baseline

    def _confirm_discard(self) -> bool:
        if not self._is_dirty():
            return True
        answer = QMessageBox.question(
            self,
            APP_NAME,
            "Discard unsaved changes?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _fill(self, name: str | None) -> None:
        """Load entry `name` into the form, or blank it for a new entry."""
        self.current = name
        if name is None:
            vals = ("",) * 5
        else:
            e = self.vault.get(name)
            vals = (name, e.username, e.url, e.password, e.notes)
        self.name_edit.setText(vals[0])
        self.user_edit.setText(vals[1])
        self.url_edit.setText(vals[2])
        self.pw_edit.setText(vals[3])
        self.notes_edit.setPlainText(vals[4])
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_btn.setText("Show")
        self.heading.setText("New entry" if name is None else "Edit entry")
        self.delete_btn.setEnabled(name is not None)
        self._baseline = vals
        self._set_status("")

    def _set_status(self, text: str, error: bool = False) -> None:
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {ERROR};" if error else "")

    def refresh_list(self, select: str | None = None) -> None:
        if self.vault is None:
            return
        target = select if select is not None else self.current
        self.listw.blockSignals(True)
        self.listw.clear()
        for name in self.vault.search(self.search.text()):
            self.listw.addItem(name)
            if name == target:
                self.listw.setCurrentRow(self.listw.count() - 1)
        self.listw.blockSignals(False)

    def _select_in_list(self, name: str | None) -> None:
        self.listw.blockSignals(True)
        self.listw.setCurrentRow(-1)
        for i in range(self.listw.count()):
            if self.listw.item(i).text() == name:
                self.listw.setCurrentRow(i)
                break
        self.listw.blockSignals(False)

    def _on_select(self, item, _previous) -> None:
        if item is None or item.text() == self.current:
            return
        if not self._confirm_discard():
            self._select_in_list(self.current)
            return
        self._fill(item.text())

    # actions

    def new_entry(self, force: bool = False) -> None:
        if not force and not self._confirm_discard():
            return
        self._select_in_list(None)
        self._fill(None)
        self.name_edit.setFocus()

    def save(self) -> None:
        if self.vault is None:
            return
        name = self.name_edit.text().strip()
        if not name:
            self._set_status("Name is required.", error=True)
            return
        old = self.current
        if name != old and name in self.vault.entries:
            self._set_status(f"An entry named {name!r} already exists.", error=True)
            return

        snapshot = dict(self.vault.entries)
        existing = self.vault.entries.get(old) if old else None
        try:
            if existing and name != old:
                self.vault.remove(old)
            entry = self.vault.add(
                name,
                username=self.user_edit.text().strip(),
                password=self.pw_edit.text(),
                url=self.url_edit.text().strip(),
                notes=self.notes_edit.toPlainText(),
                overwrite=True,
            )
            if existing:
                entry.created = existing.created
            save_vault(self.path, self.master, self.vault)
        except (VaultError, OSError) as exc:
            self.vault.entries = snapshot
            self._set_status(_sentence(str(exc)) + ".", error=True)
            return

        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.refresh_list(select=name)
        self._fill(name)
        self._set_status("Saved.")

    def delete(self) -> None:
        if self.vault is None or self.current is None:
            return
        name = self.current
        answer = QMessageBox.question(
            self,
            APP_NAME,
            f"Delete {name!r}? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        snapshot = dict(self.vault.entries)
        try:
            self.vault.remove(name)
            save_vault(self.path, self.master, self.vault)
        except (VaultError, OSError) as exc:
            self.vault.entries = snapshot
            self._set_status(_sentence(str(exc)) + ".", error=True)
            return
        self.new_entry(force=True)
        self.refresh_list()
        self._set_status("Deleted.")

    def toggle_show(self) -> None:
        hidden = self.pw_edit.echoMode() == QLineEdit.EchoMode.Password
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Normal if hidden else QLineEdit.EchoMode.Password)
        self.show_btn.setText("Hide" if hidden else "Show")

    def generate(self) -> None:
        self.pw_edit.setText(generate_password(20))
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        self.show_btn.setText("Hide")

    def copy_password(self) -> None:
        pw = self.pw_edit.text()
        if not pw:
            self._set_status("Nothing to copy.", error=True)
            return
        QGuiApplication.clipboard().setText(pw)
        self._copied = pw
        self.clip_timer.start()
        self._set_status(f"Password copied. Clipboard clears in {CLIPBOARD_CLEAR_MS // 1000} seconds.")

    def _clear_clipboard(self) -> None:
        """Clear the clipboard, but only if it still holds what we copied."""
        if self._copied is None:
            return
        clip = QGuiApplication.clipboard()
        if clip.text() == self._copied:
            clip.clear()
            if self.vault is not None:
                self._set_status("Clipboard cleared.")
        self._copied = None
        self.clip_timer.stop()

    def lock(self, force: bool = False) -> None:
        if self.vault is None:
            return
        if not force and not self._confirm_discard():
            return
        self.lock_timer.stop()
        self._clear_clipboard()
        self.vault = None
        self.master = None
        self.current = None
        self._baseline = ("",) * 5
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.listw.clear()
        self._fill(None)
        self.show_unlock()

    # events

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if self.vault is not None and event.type() in (
            QEvent.Type.KeyPress,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseMove,
            QEvent.Type.Wheel,
        ):
            self.lock_timer.start()
        return False

    def closeEvent(self, event) -> None:
        if not self._confirm_discard():
            event.ignore()
            return
        self._clear_clipboard()
        event.accept()


def make_app() -> QApplication:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")

    pal = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, BG),
        (QPalette.ColorRole.WindowText, INK),
        (QPalette.ColorRole.Base, INPUT),
        (QPalette.ColorRole.AlternateBase, SIDEBAR),
        (QPalette.ColorRole.Text, INK),
        (QPalette.ColorRole.Button, BUTTON),
        (QPalette.ColorRole.ButtonText, INK),
        (QPalette.ColorRole.PlaceholderText, MUTED),
        (QPalette.ColorRole.Highlight, SELECTED),
        (QPalette.ColorRole.HighlightedText, INK),
        (QPalette.ColorRole.ToolTipBase, INPUT),
        (QPalette.ColorRole.ToolTipText, INK),
    ):
        pal.setColor(role, QColor(color))
        app.setPalette(pal)

    font = QFont()
    font.setFamilies(FONT_FAMILIES)
    font.setPointSize(10)
    app.setFont(font)
    app.setStyleSheet(STYLE)
    return app


def run(path: Path | None = None) -> int:
    app = make_app()
    win = MainWindow(path or default_vault_path())
    win.show()
    return app.exec()


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
