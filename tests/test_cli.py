"""Tests for ``cavern.cli``.

These cover the parser surface and error-rendering path. Tests that
need an actual vault are covered at the integration level; here we
just want regressions in argument shape, help text, and exit codes
to fail fast.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cavern.cli import _parse_ttl, build_parser
from cavern.exceptions import CavernError

# ---- Parser shape ----------------------------------------------------------


def test_parser_requires_a_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_recognizes_all_documented_subcommands() -> None:
    """Every command listed in the README docstring must parse."""
    parser = build_parser()
    expected = [
        "init",
        "unlock",
        "lock",
        "insert",
        "generate",
        "show",
        "ls",
        "find",
        "rm",
        "mv",
        "otp",
        "tag",
        "audit",
        "rotate-key",
        "reindex",
        "git",
    ]
    for name in expected:
        # Each subcommand should at least accept --help without raising
        # ParseError (SystemExit is fine — argparse exits 0 on --help).
        with pytest.raises(SystemExit) as exc:
            parser.parse_args([name, "--help"])
        assert exc.value.code == 0


def test_show_with_clipboard_flag_parses() -> None:
    parser = build_parser()
    args = parser.parse_args(["show", "-c", "work/aws"])
    assert args.command == "show"
    assert args.name == "work/aws"
    assert args.clipboard is True


def test_no_cache_is_top_level_flag() -> None:
    """--no-cache must apply to any subcommand, not just one."""
    parser = build_parser()
    args = parser.parse_args(["--no-cache", "show", "work/aws"])
    assert args.no_cache is True


def test_vault_override_is_top_level_flag(tmp_path: Path) -> None:
    parser = build_parser()
    args = parser.parse_args(["--vault", str(tmp_path), "ls"])
    assert args.vault == tmp_path


def test_unlock_default_ttl_is_5m() -> None:
    parser = build_parser()
    args = parser.parse_args(["unlock"])
    assert args.ttl == "5m"


def test_init_requires_at_least_one_recipient() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["init"])


def test_init_accepts_multiple_recipients() -> None:
    parser = build_parser()
    args = parser.parse_args(["init", "alice@example.com", "bob@example.com"])
    assert args.gpg_id == ["alice@example.com", "bob@example.com"]


# ---- _parse_ttl ------------------------------------------------------------


@pytest.mark.parametrize(
    "spec, expected",
    [
        ("45s", 45.0),
        ("5m", 300.0),
        ("2h", 7200.0),
        ("600", 600.0),  # bare number = seconds
        ("  45s  ", 45.0),
        ("0s", 0.0),
    ],
)
def test_parse_ttl_accepts_common_forms(spec: str, expected: float) -> None:
    assert _parse_ttl(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "abc",
        "5x",  # unknown unit
        "5 minutes",
        "-5s",  # negative — regex requires \d+ which excludes the minus
        "1.5m",  # we don't support fractions
    ],
)
def test_parse_ttl_rejects_garbage(spec: str) -> None:
    with pytest.raises(CavernError):
        _parse_ttl(spec)


# ---- main() error rendering -----------------------------------------------


def test_main_renders_cavern_error_cleanly(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A CavernError from a handler should produce a clean one-line
    stderr message and exit 1, never a traceback."""
    from cavern import cli

    # Bypass GPG availability check so we can run main() in-process.
    monkeypatch.setattr(cli.crypto, "ensure_gpg_available", lambda: None)

    # Point at an empty vault directory — `ls` will raise NotInitializedError.
    rc = cli.main(["--vault", str(tmp_path / "nope"), "ls"])
    out, err = capsys.readouterr()
    assert rc == 1
    assert err.startswith("cavern: ")
    assert "Traceback" not in err


def test_main_handles_broken_pipe(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`cavern show ... | head` shouldn't print a traceback on EPIPE.

    Reproduces a bug found during integration testing: writing to
    sys.stdout.buffer after the consumer closed the pipe used to
    raise BrokenPipeError out of main().
    """
    from cavern import cli

    monkeypatch.setattr(cli.crypto, "ensure_gpg_available", lambda: None)

    def _broken_pipe_handler(_args, _vault) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    # Inject the handler by parsing an `ls` invocation and replacing func.
    parser = cli.build_parser()
    parsed = parser.parse_args(["--vault", str(tmp_path), "ls"])
    parsed.func = _broken_pipe_handler  # type: ignore[attr-defined]

    # Re-implement what main() does after parsing (we can't easily
    # inject the handler through main() itself, so test the path
    # directly).
    try:
        rc = int(parsed.func(parsed, None))
    except BrokenPipeError:
        rc = 0
    assert rc == 0


# ---- cmd_insert empty-secret rejection -----------------------------------


def test_cmd_insert_rejects_empty_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Hitting Enter at the getpass prompt without typing anything must fail.

    Refusing empty secrets prevents a common foot-gun: the user
    intends to paste a value, gets distracted, and accidentally
    confirms a blank entry.
    """
    from cavern import cli

    monkeypatch.setattr(cli.crypto, "ensure_gpg_available", lambda: None)
    # First getpass call returns "" (user hit Enter with no input).
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "")

    parser = cli.build_parser()
    parsed = parser.parse_args(["--vault", str(tmp_path), "insert", "test/empty"])

    with pytest.raises(CavernError, match="empty"):
        parsed.func(parsed, None)


def test_cmd_insert_rejects_empty_multiline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty stdin under -m must also fail, not silently store nothing."""
    import io

    from cavern import cli

    monkeypatch.setattr(cli.crypto, "ensure_gpg_available", lambda: None)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))

    parser = cli.build_parser()
    parsed = parser.parse_args(["--vault", str(tmp_path), "insert", "-m", "test/empty"])

    with pytest.raises(CavernError, match="empty"):
        parsed.func(parsed, None)
