# Cavern

[![CI](https://github.com/AlkaidCheng/cavern/actions/workflows/ci.yml/badge.svg)](https://github.com/AlkaidCheng/cavern/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/cavern.svg)](https://pypi.org/project/cavern/)
[![Python versions](https://img.shields.io/pypi/pyversions/cavern.svg)](https://pypi.org/project/cavern/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> A command-line credential vault. Store passwords, API keys, SSH
> passphrases, and 2FA seeds in encrypted files protected by your
> GPG identity.

## Features

- **Strong encryption.** Every secret is encrypted with AES-256-GCM,
  with authenticated decryption that detects tampering.
- **GPG-protected master key.** Unlocking the vault uses the same
  passphrase or smartcard you already use for GPG. No new password
  to remember.
- **Password generation.** Generate strong random passwords with
  configurable length, character classes, and exclusion of visually
  ambiguous characters.
- **TOTP / 2FA codes.** Store `otpauth://` URIs alongside your
  credentials and generate live time-based codes on demand.
- **Tags and search.** Tag secrets by team, environment, or project.
  Search by name substring or by tag.
- **Encrypted audit log.** Every operation is recorded in a capped,
  encrypted log you can review with `cavern audit`.
- **Git sync.** Auto-commit on every change. Push the encrypted vault
  to any git remote for backup or multi-machine sync.
- **Bulk transfer.** Export selected secrets to a passphrase-encrypted
  file for moving between machines or backing up independent of GPG;
  import a plaintext JSON file when migrating from another tool.
- **Clipboard with auto-clear.** Copy a secret to the clipboard and
  it wipes itself after 45 seconds — only if you haven't copied
  something else in the meantime.
- **Session caching.** Cache the unlocked key for a configurable
  TTL so you're not re-prompted for every command.

## What cavern is good for

- **Personal credential management** on Linux or macOS, replacing a
  plaintext password file or an unencrypted note app.
- **Storing more than passwords:** API keys, OAuth refresh tokens,
  SSH key passphrases, 2FA recovery codes, database connection
  strings, and one-time recovery phrases.
- **Multi-machine sync** without trusting a third-party service: push
  the encrypted vault to any git remote you control.
- **Workflows where the vault directory might be backed up,
  snapshotted, or copied** — and the backup itself shouldn't reveal
  what's stored inside.

## Security

- **Encrypted at rest** with industry-standard cryptography
  (AES-256-GCM authenticated encryption, HKDF for key derivation,
  256-bit keys throughout).
- **Tamper-evident.** Modifying a stored secret in any way causes
  decryption to fail with a clear error rather than silently
  returning corrupted data.
- **No plaintext metadata on disk.** A directory listing of your
  vault doesn't reveal which services you have accounts at, doesn't
  leak the size of any individual secret, and doesn't expose your
  tags. The on-disk filenames are derived from a keyed hash; secret
  sizes are bucketed.
- **Strict file permissions.** All vault files are written with
  `0600` (AlkaidCheng read/write only); the vault directory is `0700`.
- **Cheap key rotation.** Rotate the master key whenever you want;
  filenames stay the same and content ciphertexts are not
  re-encrypted, so rotation is fast even on large vaults.

For the full architecture, threat model, and the things cavern does
**not** protect against, see [`docs/SECURITY.md`](./docs/SECURITY.md)
and [`docs/KNOWN_ISSUES.md`](./docs/KNOWN_ISSUES.md). Read both before
relying on cavern for sensitive workloads.

## Install

```bash
pip install cavern              # core install
pip install cavern[totp]        # add 2FA / TOTP support
```

Requirements:

- Python 3.10 or newer
- `gpg` on `PATH` with at least one secret key
- A clipboard backend for `-c` flags: `xclip`, `xsel`, or
  `wl-clipboard` on Linux; `pbcopy` on macOS (preinstalled)
- `git`, optional, for sync support

Cavern is **POSIX-only**. Linux and macOS are supported; Windows
raises `ImportError` at import time. Use under WSL2 if you need
Windows.

## Quick start

```bash
# 1. Initialize, encrypted to your GPG identity
cavern init you@example.com

# 2. Cache the unlocked key for 10 minutes
cavern unlock --ttl 10m

# 3. Store something
cavern insert work/aws/prod         # prompts for the value, hidden

# 4. Retrieve to clipboard with 45-second auto-clear
cavern show -c work/aws/prod

# 5. Lock when you're done
cavern lock
```

## Commands

```bash
# --- Storing secrets ---
cavern insert work/github                              # prompt for value
cavern insert -m work/aws                              # multiline (paste otpauth URIs, recovery codes, etc.)
cavern generate work/db --length 32 --exclude-ambiguous

# --- Retrieving ---
cavern show work/github                                # to stdout
cavern show -c work/github                             # to clipboard, auto-clear after 45s
cavern otp work/github                                 # 2FA code (requires the totp extra)

# --- Listing & search ---
cavern ls                                              # all secret names
cavern ls work/                                        # by prefix
cavern find aws                                        # case-insensitive substring match
cavern tag work/aws cloud production critical
cavern tag --search production                         # find secrets by tag
cavern tag --list                                      # all tags currently in use

# --- Maintenance ---
cavern mv work/old work/new                            # rename
cavern rm work/old                                     # delete (with confirm)
cavern audit --limit 50                                # encrypted operation log
cavern rotate-key                                      # rotate the master key
cavern reindex                                         # reconcile the manifest with disk

# --- Bulk transfer ---
cavern dump --prefix work/ -o backup.cvd               # passphrase-encrypted export
cavern dump --tag production --armor -o -              # armored output to stdout
cavern load -i backup.cvd                              # decrypt and import
cavern bulk-insert secrets.json                        # plaintext JSON → vault (migration tool)

# --- Session control ---
cavern unlock --ttl 5m                                 # cache the unlocked key
cavern lock                                            # clear session, reload gpg-agent
cavern --no-cache show foo                             # bypass the cache for one command

# --- Git sync ---
cavern git remote add origin git@github.com:you/secrets.git
cavern git push -u origin main
```

Run `cavern --help` for the full list, or `cavern <command> --help`
for any specific subcommand.

## Documentation

- [`docs/SECURITY.md`](./docs/SECURITY.md) — threat model and
  cryptographic design
- [`docs/KNOWN_ISSUES.md`](./docs/KNOWN_ISSUES.md) — known caveats
  and to-be-fixed items
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — development setup, quality
  gates, releasing
- `cavern --help` and `cavern <command> --help` — CLI reference

## License

MIT — see [`LICENSE`](./LICENSE).
