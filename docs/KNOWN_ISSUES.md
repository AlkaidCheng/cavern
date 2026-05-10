# Known issues and caveats

This document is the inverse of [`SECURITY.md`](./SECURITY.md). That
one describes the intentional design boundaries; this one describes
the bugs, gaps, and corners we know about but haven't fixed. If
you're operating cavern in production, read this.

Items are ordered roughly by impact, most-impactful first.

## Operational caveats

### Crash mid-rotation has a narrow unrecoverable window

`cavern rotate-key` is idempotent for the common case: if the process
crashes after rewrapping some files but before others, re-running
`rotate-key` resumes cleanly because each rewrap tries the new master
key first and falls back to the old.

There is one window that is **not** recoverable automatically:

1. Every secret file has been rewrapped under the new master key.
2. The manifest and audit log have been re-encrypted.
3. The process dies *before* `master.json` is atomically replaced.

In this state, the next `cavern unlock` derives the *old* master key
from the still-untouched `master.json`, which no longer decrypts any
file. Recovery requires manually re-running the rotation with both
keys available, which cavern doesn't currently support.

In practice this requires the process to die in a ~milliseconds-wide
window, after a successful and durable write of every secret file.
Most users will never hit this.

**Mitigation:** before running `rotate-key` on a vault that matters,
take a filesystem-level snapshot of `~/.cavern/`. If something goes
wrong you can roll back the entire directory at once.

**Future fix:** write a `master.json.new` containing both old and new
wrapped master keys before rewrapping any files; promote it to
`master.json` only after every file is rewrapped; have unlock detect
and resume from the journal file. Tracked but not implemented.

### Audit log is capped, not archived

The audit log is bounded at 10 000 records. When that's exceeded, the
oldest records are dropped. There's no rotation to a separate file —
once you're at the cap, every new entry costs you the oldest one
forever.

**Mitigation:** if you want long-term audit history, periodically
copy `~/.cavern/audit` somewhere safe (it's encrypted under the
master key, so the copy is fine to keep on regular storage). After a
master-key rotation, the old copy will no longer decrypt, so archive
*before* rotating if you care about preservation.

### macOS session files are disk-backed

Repeated from `SECURITY.md` because it bites people in practice:
on macOS, `cavern unlock --ttl 5m` writes the KEK to a file under
`~/.cache/cavern/`. There is no `/dev/shm` equivalent. The kernel
can page this file to disk. **mlock on process memory does not help
the file itself.**

**Mitigation:** run with FileVault enabled (so swap is encrypted), or
use `--no-cache` to skip session caching entirely. If you use a
shorter `--ttl` (e.g., `--ttl 30s`) you reduce the exposure window
but don't eliminate it.

### Concurrent processes serialize on a per-vault flock

A second `cavern` process touching the same vault directory blocks
on `~/.cavern/.lock` until the first finishes. This is correct — it
prevents manifest read-modify-write races — but means a long-running
operation (e.g., a rotation on a large vault) blocks every other
cavern command in the same vault for its duration.

The lock is *per-vault*, not global; multiple vaults via
`CAVERN_VAULT_DIR` don't contend.

The lock is *advisory* (`flock`), not mandatory. Cooperating cavern
processes honor it. A non-cavern process editing the directory does
not, but that's already in the unsupported zone of the threat model
("attacker with write access to `~/.cavern/`").

### "Soft delete" is not implemented

`cavern rm` unlinks the file. There's no trash, no undo, no
generation history. If you remove the wrong secret, your only
recovery is your `cavern git` history (if you've been committing) or
your filesystem backups.

**Mitigation:** enable `cavern git` for the vault directory. Every
mutation auto-commits, so a bad `rm` is undoable with `cavern git
revert HEAD`.

### Bulk-insert input files are plaintext

`cavern bulk-insert <file>` is the migration path from other tools.
The input file is a plaintext JSON list and remains plaintext on disk
the entire time you're using it — cavern reads it but does **not**
delete it after import.

**Mitigation:** create the file on encrypted storage (full-disk
encryption, an encrypted USB drive, `tmpfs`); `chmod 600` before
adding any secrets; securely delete after import (`shred -u` on ext4;
on copy-on-write filesystems and SSDs, "secure delete" is not
reliable — use full-disk encryption and rotate the disk key for a
clean break). Cavern emits a warning if the input file is group- or
world-readable, but does not refuse — the choice is yours.

### Dump files are only as strong as their passphrase

`cavern dump` encrypts the bundle with AES-256-GCM under a key
derived from your passphrase via scrypt (N=2¹⁵, r=8, p=1 — ~32 MB
memory, ~300 ms to derive on a modern laptop). The scrypt parameters
are stored in the dump header so future dumps can crank cost without
breaking older files.

A weak passphrase is the only practical failure mode: scrypt makes
brute force expensive but not impossible.

**Mitigation:** use a long, random passphrase (a `cavern generate
--length 32` value works fine). Don't reuse passphrases between
dumps. Don't email a dump and the passphrase together — send them
via separate channels.

## Cryptographic caveats

### AES-GCM AAD is not bound to the file header

Each ciphertext's GCM tag covers only the content, not the header
(`magic`, `version`, `bucket_size`, the wrap nonce, etc.). An
attacker with write access who knows two filenames in your vault
could swap content from one file into the other's slot — the
ciphertext decrypts under the same master key.

In practice this requires (a) write access to your store directory
and (b) knowledge of which two HMAC-named files you want to swap. If
they have (a), they have many more interesting attacks available.

**Mitigation:** none in the current wire format. A v2 format that
binds magic+version+bucket_size into the GCM AAD would close this,
but it's a non-backwards-compatible change requiring a migration
path. Tracked but not prioritized.

### No per-file freshness counter

Each ciphertext has no monotonic counter, so an attacker with write
access can roll a file back to an earlier ciphertext (e.g., from a
backup) and the GCM tag still verifies. We do not detect rollback.

**Mitigation:** sign your `cavern git` commits and verify them
periodically; this gives you an external chain of trust on the
expected vault state. Or rely on full-disk encryption such that the
attacker doesn't have store-directory write access in the first
place.

### mlock cannot fully protect Python bytes objects

We `mlock` the specific ctypes buffer holding the session-file
envelope, so that exact buffer doesn't get paged. But Python `bytes`
objects involved in the same operations are not pinned, are
internally copyable by the runtime, and cannot be zeroed (immutable).
On a system without swap, this doesn't matter. On a system with swap,
it means the KEK *could* end up on disk via routes we don't control.

**Mitigation:** disable swap on machines that handle credentials, or
rely on full-disk encryption.

### Filename collisions are theoretically possible

We truncate `HMAC-SHA256(filename_key, name)` to 128 bits. The
birthday bound for collision probability with N entries is roughly
N²/2¹²⁹. For 10 000 secrets, that's ≈10⁻³¹ — astronomically unlikely
but not zero. There's no collision detection in `insert`; if you hit
one, the insert silently overwrites the previous file.

**Mitigation:** none needed in practice. Documented for completeness.

## Operational gaps

### No `--dry-run` for `rotate-key`

You can't preview what `rotate-key` would do without actually doing
it. The operation is fast and idempotent, but a `--dry-run` mode
that reports "would rewrap N files" would be polite. Tracked.

### No bulk export / import

There's no `cavern export > backup.tar` or `cavern import < backup.tar`
flow. To migrate vaults across machines, copy `~/.cavern/` directly
(the directory is self-contained) and ensure the destination has the
GPG private key for one of the recipients.

### No password-strength feedback in `generate`

`cavern generate --length 8` will happily produce an 8-character
password. There's no warning, no minimum, no strength indicator.
Pick a sensible default length yourself; we picked 24 as the default
because it's strong without being unwieldy.

### Clipboard auto-clear assumes UTF-8 round-trip

The auto-clear cleaner copies your secret to the clipboard, sleeps
the configured duration, then clears the clipboard *only if* the
current clipboard content still equals the original secret. If you
copy something else in the meantime, the cleaner leaves your
clipboard alone — which is the right behavior.

There's an edge case: if your secret contains a trailing newline
*and* you're on Wayland, `wl-paste --no-newline` strips one trailing
newline on read, so the round-trip differs and the cleaner refuses to
clear (safe failure mode — your secret stays on the clipboard). In
practice passwords don't end in newlines, so this is rarely an issue.

### Windows isn't supported, period

Cavern raises `ImportError` at package import time on Windows.
Several features fundamentally don't translate (POSIX file modes,
uid-aware paths, `mlock(2)`, detached subprocess sessions). Use
under WSL2 if you need Windows.

## To-be-fixed items

The following are tracked for future work but not yet implemented.
Each is **not** a security regression — they're enhancements.

- [ ] Transactional `rotate-key` via `master.json.new` journal (closes the narrow unrecoverable window)
- [ ] AES-GCM AAD binding to file header (v2 wire format)
- [ ] `--dry-run` flag for `rotate-key`
- [ ] `cavern export` / `cavern import` for bulk migration
- [ ] Optional per-file freshness counter (rollback detection)
- [ ] Configurable audit log retention (rotation to archive files)

## Reporting an issue

If you find a security issue not covered above, please report it
privately rather than opening a public issue. See [`SECURITY.md`](./SECURITY.md)
for what's in and out of scope.
