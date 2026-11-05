"""Command-line interface for pwman."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .crypto import VaultError
from .generator import MIN_LENGTH, generate_password
from .vault import create_vault, default_vault_path, load_vault, save_vault

MIN_MASTER_LEN = 12


def _prompt_new_password(label: str) -> str:
    first = getpass.getpass(f"{label}: ")
    if getpass.getpass(f"Confirm {label.lower()}: ") != first:
        raise VaultError("passwords do not match")
    if not first:
        raise VaultError("password cannot be empty")
    return first


def _open(path: Path):
    if not path.exists():
        raise VaultError(f"no vault at {path}; run `pwman init` first")
    master = getpass.getpass("Master password: ")
    return master, load_vault(path, master)


# --------------------------------------------------------------- commands


def cmd_init(args: argparse.Namespace) -> int:
    path: Path = args.vault
    if path.exists():
        raise VaultError(f"a vault already exists at {path}")
    master = _prompt_new_password("New master password")
    if len(master) < MIN_MASTER_LEN:
        raise VaultError(f"master password must be at least {MIN_MASTER_LEN} characters")
    create_vault(path, master)
    print(f"Created vault at {path}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    master, vault = _open(args.vault)
    if args.generate:
        password = generate_password(args.length, symbols=not args.no_symbols)
    else:
        password = _prompt_new_password(f"Password for {args.name}")
    vault.add(
        args.name,
        username=args.username or "",
        password=password,
        url=args.url or "",
        notes=args.notes or "",
        overwrite=args.force,
    )
    save_vault(args.vault, master, vault)
    print(f"Saved {args.name!r}")
    if args.generate:
        print(f"Generated password: {password}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    _, vault = _open(args.vault)
    names = vault.names()
    if not names:
        print("(vault is empty)")
        return 0
    for name in names:
        user = vault.entries[name].username
        print(f"{name}  [{user}]" if user else name)
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    _, vault = _open(args.vault)
    e = vault.get(args.name)
    print(f"name:     {args.name}")
    print(f"username: {e.username}")
    if e.url:
        print(f"url:      {e.url}")
    if e.notes:
        print(f"notes:    {e.notes}")
    print(f"updated:  {e.updated}")
    print(f"password: {e.password if args.show else '********  (use --show to reveal)'}")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    master, vault = _open(args.vault)
    vault.get(args.name)  # raises if missing
    if not args.yes and input(f"Delete {args.name!r}? [y/N] ").strip().lower() != "y":
        print("Aborted")
        return 1
    vault.remove(args.name)
    save_vault(args.vault, master, vault)
    print(f"Removed {args.name!r}")
    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    print(generate_password(args.length, symbols=not args.no_symbols))
    return 0


# ----------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwman", description="Local encrypted password manager")
    p.add_argument("--version", action="version", version=f"pwman {__version__}")
    p.add_argument(
        "--vault",
        type=Path,
        default=None,
        help="vault file (default: $PWMAN_VAULT or ~/.local/share/pwman/vault.enc)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    a = sub.add_parser("add", help="add or replace an entry")
    a.add_argument("name")
    a.add_argument("-u", "--username")
    a.add_argument("--url")
    a.add_argument("--notes")
    a.add_argument("-g", "--generate", action="store_true", help="generate the password")
    a.add_argument("-l", "--length", type=int, default=20)
    a.add_argument("--no-symbols", action="store_true")
    a.add_argument("-f", "--force", action="store_true", help="overwrite existing entry")
    a.set_defaults(func=cmd_add)

    sub.add_parser("list", help="list entry names").set_defaults(func=cmd_list)

    g = sub.add_parser("get", help="show an entry")
    g.add_argument("name")
    g.add_argument("--show", action="store_true", help="print the password")
    g.set_defaults(func=cmd_get)

    r = sub.add_parser("rm", help="remove an entry")
    r.add_argument("name")
    r.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    r.set_defaults(func=cmd_rm)

    n = sub.add_parser("gen", help="generate a password without storing it")
    n.add_argument("-l", "--length", type=int, default=20)
    n.add_argument("--no-symbols", action="store_true")
    n.set_defaults(func=cmd_gen)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.vault = args.vault or default_vault_path()
    try:
        return args.func(args)
    except (VaultError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\naborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
