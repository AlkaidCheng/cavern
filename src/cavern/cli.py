"""Command-line interface for cavern.

Subcommand summary::

    cavern init <gpg-id>...
    cavern unlock [--ttl 5m]              # cache KEK in mlock'd session file
    cavern lock                           # clear session + reload gpg-agent
    cavern insert [--force] <name>        # prompts for value (never on argv)
    cavern generate [-l N] [--no-symbols] [--exclude-ambiguous] [-c] [-f] <name>
    cavern show [-c] [--no-cache] <name>
    cavern ls [<prefix>]
    cavern find <pattern>
    cavern mv [-f] <from> <to>
    cavern rm [-f] <name>
    cavern otp [-c] <name>
    cavern tag <name> <tag>... | --list | --search <tag>
    cavern audit [--limit N]
    cavern rotate-key                     # rotate master key (cheap O(n))
    cavern reindex                        # reconcile manifest with disk
    cavern git <args>...

Errors derive from :class:`CavernError`; the CLI catches the base
class, prints ``cavern: <message>`` to stderr, and exits non-zero.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import re
import sys
from pathlib import Path
from typing import BinaryIO

from . import crypto, git, session
from .audit import AuditLog
from .clipboard import DEFAULT_CLEAR_AFTER, copy_with_autoclear
from .exceptions import CavernError, GitError, NotInitializedError
from .generator import PasswordPolicy, generate_password
from .totp import current_totp
from .vault import UnlockedKeys, Vault

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auto_commit(vault: Vault, message: str) -> None:
    """Auto-commit on mutations; never abort the CLI if git fails."""
    try:
        git.commit_all(vault.root, message)
    except GitError as exc:
        print(f"cavern: warning: git auto-commit skipped — {exc}", file=sys.stderr)


def _parse_ttl(spec: str) -> float:
    """Parse a TTL spec like ``5m``, ``2h``, ``45s``, ``600`` into seconds."""
    match = re.fullmatch(r"\s*(\d+)\s*([smh]?)\s*", spec)
    if not match:
        raise CavernError(f"Invalid TTL: {spec!r}. Use e.g. 45s, 5m, 2h.")
    value = int(match.group(1))
    unit = match.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def _resolve_keys(vault: Vault, *, no_cache: bool) -> UnlockedKeys:
    """Get the unlocked keys, preferring the session cache when available.

    When ``no_cache`` is true, always invoke GPG. Otherwise fall back
    to GPG only if the session is absent.
    """
    if not no_cache:
        try:
            kek = session.read_session()
            return vault.derive_keys(kek)
        except CavernError:
            pass  # fall through to GPG
    kek = vault.unlock_with_gpg()
    return vault.derive_keys(kek)


def _normalize_name(name: str) -> str:
    """Normalize a secret name at the CLI boundary.

    The vault layer also normalizes (so the on-disk filename is
    consistent), but normalizing once at the CLI ensures the audit
    log, git commit messages, and user-facing prompts all show the
    same canonical form rather than echoing back the raw argv.
    """
    normalized = name.strip()
    if not normalized:
        raise CavernError("Secret name cannot be empty.")
    return normalized


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, vault: Vault) -> int:
    _ensure_recipients_or_offer_keygen(args.gpg_id)
    keys = vault.init(args.gpg_id)
    git.init(vault.root)
    _auto_commit(vault, f"Initialize vault with GPG id {' '.join(args.gpg_id)}")
    AuditLog(vault.root, keys.master_key).append("init", recipients=list(args.gpg_id))
    print(f"Initialized empty cavern vault at {vault.root}")
    return 0


def _ensure_recipients_or_offer_keygen(recipients: list[str]) -> None:
    """Pre-flight check that every recipient has a usable GPG secret key.

    When run on a TTY and a key is missing, offer to launch
    ``gpg --full-generate-key`` interactively. Off a TTY (CI, scripts,
    tests), skip the prompt and just raise — silent prompting in
    automated contexts is worse than failing fast.

    Re-checks after a wizard run because the user may have generated
    a key under a different identity than the one passed to
    ``cavern init``.
    """
    try:
        crypto.ensure_recipients_have_secret_keys(recipients)
        return
    except CavernError as exc:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise
        # Print the diagnostic before the prompt so the user sees what
        # went wrong before deciding.
        print(f"cavern: {exc}", file=sys.stderr)
        print(file=sys.stderr)

    answer = (
        input("Run `gpg --full-generate-key` to create a new key now? [y/N] ")
        .strip()
        .lower()
    )
    if answer not in {"y", "yes"}:
        raise CavernError("Vault initialization aborted; no GPG key available.")

    rc = crypto.gpg_run_keygen_wizard()
    if rc != 0:
        raise CavernError(
            f"gpg key generation exited with status {rc}; "
            f"vault initialization aborted."
        )

    # The user may have generated a key with a uid that doesn't match
    # the identifier they passed to `cavern init`. Re-check so we
    # surface the mismatch immediately rather than at encryption time.
    crypto.ensure_recipients_have_secret_keys(recipients)


def cmd_unlock(args: argparse.Namespace, vault: Vault) -> int:
    ttl = _parse_ttl(args.ttl)
    kek = vault.unlock_with_gpg()
    path, locked = session.write_session(kek, ttl)
    print(f"Vault unlocked. Session expires in {int(ttl)}s.")
    if not locked:
        print(
            "cavern: warning: could not mlock session memory. "
            "On Linux, raise RLIMIT_MEMLOCK or run as root.",
            file=sys.stderr,
        )
    return 0


def cmd_lock(_args: argparse.Namespace, _vault: Vault) -> int:
    session.clear_session()
    crypto.gpg_reload_agent()
    print("Vault locked: session cleared and gpg-agent reloaded.")
    return 0


def cmd_insert(args: argparse.Namespace, vault: Vault) -> int:
    name = _normalize_name(args.name)
    if args.multiline:
        print(
            f"Enter contents of {name} (Ctrl-D to finish):",
            file=sys.stderr,
        )
        plaintext = sys.stdin.read().encode("utf-8")
        if not plaintext:
            raise CavernError("Refusing to store an empty secret.")
    else:
        # getpass keeps the value off-screen and out of shell history.
        secret = getpass.getpass(f"Enter value for {name}: ")
        if not secret:
            raise CavernError("Refusing to store an empty secret.")
        confirm = getpass.getpass(f"Retype value for {name}: ")
        if secret != confirm:
            raise CavernError("Values do not match.")
        plaintext = secret.encode("utf-8")

    keys = _resolve_keys(vault, no_cache=args.no_cache)
    vault.insert(keys, name, plaintext, force=args.force)
    AuditLog(vault.root, keys.master_key).append("insert", name)
    _auto_commit(vault, f"Insert {name}")
    return 0


def cmd_generate(args: argparse.Namespace, vault: Vault) -> int:
    name = _normalize_name(args.name)
    policy = PasswordPolicy(
        length=args.length,
        use_symbols=not args.no_symbols,
        exclude_ambiguous=args.exclude_ambiguous,
    )
    password = generate_password(policy)

    keys = _resolve_keys(vault, no_cache=args.no_cache)
    vault.insert(keys, name, password.encode("utf-8"), force=args.force)
    AuditLog(vault.root, keys.master_key).append("generate", name, length=policy.length)
    _auto_commit(vault, f"Generate {name}")

    if args.clipboard:
        copy_with_autoclear(password)
        print(f"Generated value for {name} copied to clipboard.")
        print(f"Will clear in {int(DEFAULT_CLEAR_AFTER)} seconds.")
    else:
        print(password)
    return 0


def cmd_show(args: argparse.Namespace, vault: Vault) -> int:
    name = _normalize_name(args.name)
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    plaintext = vault.show(keys, name)
    AuditLog(vault.root, keys.master_key).append("show", name, clipboard=args.clipboard)

    if args.clipboard:
        # Only the first line is copied to the clipboard — the rest
        # (if any) is metadata. This matches `pass`'s convention.
        first_line = plaintext.split(b"\n", 1)[0].decode("utf-8")
        copy_with_autoclear(first_line)
        print(f"Copied {name} to clipboard.")
        print(f"Will clear in {int(DEFAULT_CLEAR_AFTER)} seconds.")
        return 0

    sys.stdout.buffer.write(plaintext)
    if not plaintext.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    return 0


def cmd_ls(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    names = vault.list_names(keys)
    if args.prefix:
        names = [n for n in names if n.startswith(args.prefix)]
    if not names:
        print("(empty)")
        return 0
    for name in names:
        print(name)
    return 0


def cmd_find(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    matches = vault.find(keys, args.pattern)
    if not matches:
        print("(no matches)")
        return 1
    for name in matches:
        print(name)
    return 0


def cmd_rm(args: argparse.Namespace, vault: Vault) -> int:
    name = _normalize_name(args.name)
    if not args.force:
        confirm = input(f"Really delete {name}? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return 1
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    vault.remove(keys, name)
    AuditLog(vault.root, keys.master_key).append("rm", name)
    _auto_commit(vault, f"Remove {name}")
    return 0


def cmd_mv(args: argparse.Namespace, vault: Vault) -> int:
    source = _normalize_name(args.source)
    target = _normalize_name(args.target)
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    vault.move(keys, source, target, force=args.force)
    AuditLog(vault.root, keys.master_key).append("mv", source, target=target)
    _auto_commit(vault, f"Rename {source} -> {target}")
    return 0


def cmd_otp(args: argparse.Namespace, vault: Vault) -> int:
    name = _normalize_name(args.name)
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    plaintext = vault.show(keys, name)
    code = current_totp(plaintext)
    AuditLog(vault.root, keys.master_key).append("otp", name, clipboard=args.clipboard)

    if args.clipboard:
        copy_with_autoclear(code)
        print(f"TOTP for {name} copied to clipboard.")
        print(f"Will clear in {int(DEFAULT_CLEAR_AFTER)} seconds.")
    else:
        print(code)
    return 0


def cmd_tag(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)

    if args.list:
        tags = vault.all_tags(keys)
        if not tags:
            print("(no tags)")
            return 0
        for tag in tags:
            print(tag)
        return 0

    if args.search:
        names = vault.search_by_tag(keys, args.search)
        if not names:
            print("(no matches)")
            return 1
        for name in names:
            print(name)
        return 0

    if not args.name or not args.tags:
        raise CavernError(
            "Provide a name and one or more tags, or use --list/--search."
        )
    name = _normalize_name(args.name)
    vault.set_tags(keys, name, args.tags)
    AuditLog(vault.root, keys.master_key).append("tag", name, tags=args.tags)
    _auto_commit(vault, f"Tag {name}: {' '.join(args.tags)}")
    return 0


def cmd_audit(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    records = AuditLog(vault.root, keys.master_key).recent(limit=args.limit)
    if not records:
        print("(audit log is empty)")
        return 0

    import datetime as _dt

    for record in records:
        timestamp = _dt.datetime.fromtimestamp(record["ts"]).isoformat(
            timespec="seconds"
        )
        action = record.get("action", "?")
        name = record.get("name", "")
        print(f"{timestamp}  {action:<10} {name}")
    return 0


def cmd_rotate_key(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    print("Rotating master key (rewrapping all secret headers)...")
    count = vault.rotate_master_key(keys)
    # Reload from the new master.json and write the audit entry under the new key.
    new_keys = vault.derive_keys(keys.kek)
    AuditLog(vault.root, new_keys.master_key).append("rotate-key", count=count)
    _auto_commit(vault, "Rotate master key")
    print(f"Done. Rewrapped {count} secret(s). Filenames unchanged.")
    return 0


def cmd_reindex(args: argparse.Namespace, vault: Vault) -> int:
    keys = _resolve_keys(vault, no_cache=args.no_cache)
    orphans, missing = vault.audit_drift(keys)
    if orphans:
        print(f"{len(orphans)} orphan file(s) in store/ not in manifest:")
        for o in orphans:
            print(f"  {o}")
        print("(orphans cannot be auto-recovered — original names are unknown)")
    removed = vault.reindex(keys)
    AuditLog(vault.root, keys.master_key).append(
        "reindex", orphans=len(orphans), removed=removed
    )
    _auto_commit(vault, "Reindex manifest")
    print(f"Removed {removed} stale manifest entr{'y' if removed == 1 else 'ies'}.")
    return 0


def cmd_git(args: argparse.Namespace, vault: Vault) -> int:
    return git.passthrough(vault.root, args.git_args)


def cmd_dump(args: argparse.Namespace, vault: Vault) -> int:
    """Encrypted bulk export.

    Prompts (twice) for a passphrase, then writes the dump either to
    a named file or to stdout. The passphrase is the *only* thing
    protecting the dump — pick a strong one.
    """
    from .bulk import dump_secrets

    passphrase = getpass.getpass("Passphrase for dump: ")
    if not passphrase:
        raise CavernError("Passphrase cannot be empty.")
    confirm = getpass.getpass("Retype passphrase: ")
    if passphrase != confirm:
        raise CavernError("Passphrases do not match.")

    keys = _resolve_keys(vault, no_cache=args.no_cache)

    output_stream: BinaryIO
    if args.output == "-":
        output_stream = sys.stdout.buffer
        close_after = False
    else:
        output_path = Path(args.output)
        output_stream = output_path.open("wb")
        close_after = True
        # Tighten permissions immediately — the dump is encrypted but
        # there's no reason for it to be world-readable.
        os.chmod(output_path, 0o600)

    try:
        result = dump_secrets(
            vault,
            keys,
            passphrase,
            output_stream,
            prefix=args.prefix,
            tags=args.tag or None,
            armor=args.armor,
        )
    finally:
        if close_after:
            output_stream.close()

    AuditLog(vault.root, keys.master_key).append(
        "dump",
        count=result.secret_count,
        prefix=args.prefix,
        tags=args.tag or [],
        armor=args.armor,
    )

    if args.output == "-":
        # Don't print summary to stdout — it would corrupt the dump.
        print(
            f"Wrote {result.secret_count} secret(s), "
            f"{result.bytes_written} bytes to stdout.",
            file=sys.stderr,
        )
    else:
        print(
            f"Wrote {result.secret_count} secret(s) to {args.output} "
            f"({result.bytes_written} bytes)."
        )
    return 0


def cmd_load(args: argparse.Namespace, vault: Vault) -> int:
    """Decrypt a dump and import each secret."""
    from .bulk import load_secrets

    passphrase = getpass.getpass("Passphrase for dump: ")
    if not passphrase:
        raise CavernError("Passphrase cannot be empty.")

    if args.input == "-":
        input_data = sys.stdin.buffer.read()
    else:
        input_path = Path(args.input)
        if not input_path.is_file():
            raise CavernError(f"Dump file not found: {input_path}")
        input_data = input_path.read_bytes()

    keys = _resolve_keys(vault, no_cache=args.no_cache)
    result = load_secrets(vault, keys, passphrase, input_data, overwrite=args.overwrite)

    AuditLog(vault.root, keys.master_key).append(
        "load",
        inserted=result.inserted,
        skipped=result.skipped,
        overwritten=result.overwritten,
    )
    _auto_commit(
        vault,
        f"Bulk load: {result.inserted} inserted, " f"{result.overwritten} overwritten",
    )

    print(
        f"Loaded: {result.inserted} new, "
        f"{result.overwritten} overwritten, "
        f"{result.skipped} skipped (already present; use --overwrite to replace)."
    )
    return 0


def cmd_bulk_insert(args: argparse.Namespace, vault: Vault) -> int:
    """Insert many secrets from a plaintext JSON file."""
    from .bulk import bulk_insert_from_file

    file_path = Path(args.file)

    keys = _resolve_keys(vault, no_cache=args.no_cache)
    result, warnings = bulk_insert_from_file(
        vault, keys, file_path, overwrite=args.overwrite
    )

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    AuditLog(vault.root, keys.master_key).append(
        "bulk-insert",
        source=str(file_path),
        inserted=result.inserted,
        skipped=result.skipped,
        overwritten=result.overwritten,
    )
    _auto_commit(
        vault,
        f"Bulk insert from {file_path.name}: {result.inserted} new, "
        f"{result.overwritten} overwritten",
    )

    print(
        f"Inserted: {result.inserted} new, "
        f"{result.overwritten} overwritten, "
        f"{result.skipped} skipped (already present; use --overwrite to replace)."
    )
    print(
        f"\nNote: {file_path} is plaintext. Delete it securely "
        f"(e.g. `shred -u {file_path}` on ext4) once you've verified "
        f"the import.",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="cavern",
        description="Encrypted command-line credential vault.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        help="Vault root (default: $CAVERN_VAULT_DIR or ~/.cavern).",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass session cache; always prompt via GPG/pinentry.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p = sub.add_parser("init", help="Initialize a new vault.")
    p.add_argument(
        "gpg_id",
        nargs="+",
        help="One or more GPG key IDs, fingerprints, or email addresses "
        "to encrypt the vault to.",
    )
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("unlock", help="Cache the KEK for a TTL.")
    p.add_argument(
        "--ttl",
        default="5m",
        help="Session lifetime: bare digits = seconds, suffix s/m/h " "(default: 5m).",
    )
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("lock", help="Clear session and reload gpg-agent.")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("insert", help="Insert a new secret (prompts for value).")
    p.add_argument("name", help="Secret name, e.g. 'work/aws/prod'.")
    p.add_argument(
        "-m",
        "--multiline",
        action="store_true",
        help="Read the entire value from stdin until EOF "
        "(useful for multi-line secrets like otpauth URIs).",
    )
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite the secret if it already exists.",
    )
    p.set_defaults(func=cmd_insert)

    p = sub.add_parser("generate", help="Generate and store a random password.")
    p.add_argument("name", help="Secret name, e.g. 'work/github'.")
    p.add_argument(
        "-l",
        "--length",
        type=int,
        default=24,
        help="Password length in characters (default: 24).",
    )
    p.add_argument(
        "--no-symbols",
        action="store_true",
        help="Use only letters and digits (no punctuation).",
    )
    p.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Drop visually ambiguous characters (0/O, 1/l/I, etc.).",
    )
    p.add_argument(
        "-c",
        "--clipboard",
        action="store_true",
        help="Copy the generated password to the clipboard with auto-clear "
        "instead of printing it.",
    )
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite the secret if it already exists.",
    )
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("show", help="Decrypt and display a secret.")
    p.add_argument("name", help="Secret name to display.")
    p.add_argument(
        "-c",
        "--clipboard",
        action="store_true",
        help="Copy the first line of the secret to the clipboard with "
        "auto-clear instead of printing it.",
    )
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("ls", help="List secret names.")
    p.add_argument(
        "prefix",
        nargs="?",
        default=None,
        help="Optional name prefix to filter by, e.g. 'work/'.",
    )
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("find", help="Find secrets by name substring.")
    p.add_argument(
        "pattern",
        help="Case-insensitive substring to search for in secret names.",
    )
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("rm", help="Remove a secret.")
    p.add_argument("name", help="Secret name to remove.")
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Skip the confirmation prompt.",
    )
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("mv", help="Rename a secret.")
    p.add_argument("source", help="Existing secret name.")
    p.add_argument("target", help="New name for the secret.")
    p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite the target if it already exists.",
    )
    p.set_defaults(func=cmd_mv)

    p = sub.add_parser("otp", help="Generate TOTP from a secret's otpauth URI.")
    p.add_argument(
        "name",
        help="Secret containing an 'otpauth://' URI on one of its lines.",
    )
    p.add_argument(
        "-c",
        "--clipboard",
        action="store_true",
        help="Copy the generated code to the clipboard with auto-clear "
        "instead of printing it.",
    )
    p.set_defaults(func=cmd_otp)

    p = sub.add_parser("tag", help="Manage encrypted tags.")
    p.add_argument("name", nargs="?", default=None, help="Secret to tag.")
    p.add_argument(
        "tags",
        nargs="*",
        help="One or more tags to set on the secret (replaces existing tags).",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="List every tag that has been used in the vault.",
    )
    p.add_argument(
        "--search",
        metavar="TAG",
        default=None,
        help="Find every secret carrying the given tag.",
    )
    p.set_defaults(func=cmd_tag)

    p = sub.add_parser("audit", help="View the encrypted audit log.")
    p.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of records to show, newest first (default: 100).",
    )
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser(
        "rotate-key",
        help="Rotate the master key (rewraps headers; content untouched).",
    )
    p.set_defaults(func=cmd_rotate_key)

    p = sub.add_parser(
        "reindex",
        help="Reconcile the manifest with the on-disk store directory.",
    )
    p.set_defaults(func=cmd_reindex)

    p = sub.add_parser("git", help="Run a git command in the vault.")
    p.add_argument(
        "git_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded verbatim to 'git'.",
    )
    p.set_defaults(func=cmd_git)

    p = sub.add_parser(
        "dump",
        help="Encrypted bulk export of (filtered) secrets to a file.",
        description=(
            "Export selected secrets to a passphrase-encrypted file. "
            "The dump is a self-contained blob that can be moved between "
            "machines, emailed, or backed up; only the passphrase you "
            "provide is required to decrypt it. Pick a strong one — it "
            "is the only thing protecting the dump."
        ),
    )
    p.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output path. Use '-' to write to stdout.",
    )
    p.add_argument(
        "--prefix",
        default=None,
        help="Only include secrets whose names start with this prefix.",
    )
    p.add_argument(
        "--tag",
        action="append",
        default=None,
        help="Only include secrets carrying this tag (repeatable; OR semantics).",
    )
    p.add_argument(
        "--armor",
        action="store_true",
        help="ASCII-armor the output (base64 with BEGIN/END markers) "
        "for safe transport over email or the clipboard.",
    )
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser(
        "load",
        help="Decrypt a dump file and import each secret.",
        description=(
            "Read a passphrase-encrypted dump (binary or ASCII-armored) "
            "and insert each secret into the current vault. Secrets that "
            "already exist are skipped unless --overwrite is passed."
        ),
    )
    p.add_argument(
        "-i",
        "--input",
        required=True,
        help="Input path. Use '-' to read from stdin.",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing secrets instead of skipping them.",
    )
    p.set_defaults(func=cmd_load)

    p = sub.add_parser(
        "bulk-insert",
        help="Insert many secrets from a plaintext JSON file.",
        description=(
            "Read a plaintext JSON file and insert each entry. The file "
            'must be a JSON list of {"name", "value", "tags"?} '
            "objects. The file is plaintext by design (use case: "
            "migration from another tool); store it on encrypted media "
            "and securely delete it after the import completes."
        ),
    )
    p.add_argument(
        "file",
        help="Path to the plaintext JSON file.",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing secrets instead of skipping them.",
    )
    p.set_defaults(func=cmd_bulk_insert)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


# Commands that may run on a directory that isn't yet a cavern vault.
# Everything else is rejected up front with a clear hint, before the
# command handler runs, so that handlers and their downstream calls
# (subprocess invocations of git, etc.) can assume the vault exists.
_COMMANDS_WITHOUT_INIT: frozenset[str] = frozenset({"init"})


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    crypto.ensure_gpg_available()
    vault = Vault(root=args.vault)

    try:
        if args.command not in _COMMANDS_WITHOUT_INIT and not vault.is_initialized():
            raise NotInitializedError(
                f"No vault at {vault.root}.\n"
                f"  Run `cavern init <gpg-id>` to create one, or set "
                f"$CAVERN_VAULT_DIR / pass --vault to point at an "
                f"existing vault."
            )
        return int(args.func(args, vault))
    except CavernError as exc:
        print(f"cavern: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except BrokenPipeError:
        # Common in pipelines like `cavern show foo | head`. Python's
        # default handler prints a traceback; we silently exit 0 like
        # a well-behaved Unix tool. Closing stderr stops the
        # interpreter shutdown from trying to flush to the
        # already-closed pipe and complaining again.
        with contextlib.suppress(OSError):
            sys.stderr.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
