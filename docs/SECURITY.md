# Security model

This document describes what cavern protects against, what it
doesn't, and what assumptions it makes about its operating
environment. If you're evaluating cavern for a real workload, read
this carefully.

For *known issues, caveats, and items not yet fixed*, see
[`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md). This document covers the
intentional design boundaries; that one covers the bugs and gaps.

## Architecture

### Key hierarchy

```
GPG passphrase
    └─ decrypts master.gpg
            └─ KEK (32 random bytes, never rotates)
                    ├─ HKDF(KEK, "filename-v1") → filename_key
                    │       └─ HMAC(filename_key, name)[:16] → on-disk filename
                    └─ HKDF(KEK, "wrap-v1")     → wrap_key
                            └─ AES-GCM-wraps master_key (rotatable)
                                    └─ AES-GCM-wraps per-file DEKs
```

The KEK exists only to derive the two persistent subkeys. The
filename key never rotates, so master-key rotation does not rename
files. The wrap key wraps a separate, rotatable master key, so
rotation rewraps a small DEK header per file rather than re-encrypting
content. The master key wraps per-file DEKs, so a leaked DEK reveals
nothing about another secret.

### File format

Each secret on disk:

```
[magic:        4 bytes  = b"CVRN"]
[version:      1 byte   = 0x01]
[wrap_nonce:  12 bytes]
[wrapped_dek: 48 bytes  (32 ciphertext + 16 GCM tag)]
[content_nonce: 12 bytes]
[bucket_size:  4 bytes  big-endian uint32]
[content_ct:   bucket_size + 16 bytes  (padded plaintext + GCM tag)]
```

Total fixed overhead is 97 bytes; the version byte exists so a v2
wire format can land without breaking v1 vaults. Padding uses ISO/IEC
7816-4 to one of four buckets (256 B / 1 KiB / 4 KiB / 16 KiB).

### Session cache

`cavern unlock --ttl Xm` writes the unwrapped KEK to a session file:

- **Linux:** `/dev/shm/cavern/session-<uid>` — tmpfs, in-RAM.
- **macOS / other POSIX:** `~/.cache/cavern/session-<uid>` — disk-backed.

The session file format is `[magic][version][token (16 B random)][KEK (32 B)]`,
mode `0o600`. A detached cleaner unlinks the file when the TTL elapses,
and only if the on-disk token matches what it was launched with — so
running `cavern unlock` twice doesn't have the first cleaner delete
the second session's file.

Open uses `O_NOFOLLOW | O_CLOEXEC | O_EXCL` to defeat symlink swap
attacks; ownership and mode are validated via `fstat` on the same fd
that's then read, eliminating the path-stat-then-read TOCTOU.

## Threat model

### Protected

Read access to `~/.cavern/` does not reveal:

- the names of any secret,
- the contents of any secret,
- the exact length of any secret (only one of four bucket sizes),
- the tags on any secret,
- which secrets share a tag,
- access patterns over time (beyond what `mtime` reveals — see
  *Partially protected* below).

An attacker who steals a backup of your store learns the count of
secrets and the bucket size of each. That's it.

### Partially protected

- **Modification times.** The filesystem records when each file was
  last written. An attacker watching `mtime` can correlate "you used
  cavern at 15:42" with external events. Mitigate by storing on a
  filesystem mounted with `noatime` and `nodiratime`, or by holding
  the vault on full-disk encryption that is dismounted when not in
  use.
- **Process memory.** Plaintexts pass through Python `bytes` objects
  during normal operations. Python's runtime can produce internal
  copies we cannot reach, and `bytes` is immutable so we cannot zero
  it. We `mlock` the specific buffers we hand to ctypes (the KEK
  envelope, primarily) but **mlock is harm reduction, not a guarantee**.
  For sensitive deployments, run on top of full-disk encryption so
  that any swap, hibernate, or core dump is encrypted.
- **macOS session files.** macOS has no `/dev/shm` equivalent, so
  the session file lives in `~/.cache/cavern/`, which is disk-backed.
  The kernel can page this file to disk regardless of any
  process-level mitigation. **This is a meaningful gap on macOS, not
  a footnote.** Run with FileVault enabled, or pass `--no-cache` to
  bypass session caching entirely (each command will then prompt via
  GPG agent).
- **The `recipients` file is plaintext.** Cavern needs to know who
  to encrypt `master.gpg` to when you change recipients, which means
  the recipients list itself sits unencrypted in the vault directory.
  An attacker with read access learns the GPG identities, but not
  the contents encrypted to them. If even the identity list is
  sensitive, store the recipients out-of-band and pass them on the
  command line each time you re-encrypt.

### Not protected

- **Active attackers with write access to `~/.cavern/`.** Authenticated
  encryption catches silent tampering, but not *substitution*: an
  attacker can swap in a known-good ciphertext from an earlier
  backup, or revert a file to its previous version. There is no
  per-file freshness counter or signed manifest. Mitigate with
  full-disk encryption or by signing your `cavern git` commits.
- **Catastrophic loss of `master.gpg` or the GPG private key.** Total
  data loss. **Back up your GPG key.**
- **"Secure delete."** On copy-on-write filesystems (APFS, Btrfs, ZFS)
  and SSDs with wear leveling, overwriting a file in place does not
  reliably erase its contents. Cavern's `rm` unlinks the file via
  the standard POSIX call; that's all it can do. If you need
  forensic-resistant deletion, run cavern on full-disk encryption
  and rotate the disk key when you need a clean break.
- **Side-channel attacks against `cryptography`'s AES-GCM
  implementation.** We use the upstream library as-is. Constant-time
  guarantees are theirs, not ours.
- **Compromise of the running cavern process** (e.g., a malicious
  Python package in your environment). The KEK is in memory and any
  in-process attacker can read it. Cavern is not designed to defend
  against attackers with code execution in the same Python
  interpreter.

## Cryptographic primitives

| Purpose | Algorithm | Key size |
| --- | --- | --- |
| Outer KEK envelope | GPG (whatever your `master.gpg` recipients use) | (per recipient) |
| KEK → subkey derivation | HKDF-SHA256 | 256-bit output |
| Filename hashing | HMAC-SHA256, truncated to 128 bits | 256-bit key |
| Master-key wrapping | AES-256-GCM | 256-bit key |
| DEK wrapping | AES-256-GCM | 256-bit key |
| Content encryption | AES-256-GCM | 256-bit DEK (fresh per file) |
| Random generation | `os.urandom` / `secrets` | OS CSPRNG |

All AES-GCM nonces are 12 random bytes generated by `os.urandom` per
encryption call. Nonces are never reused under the same key.

## See also

- [`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md) — known caveats, gaps, and
  to-be-fixed items not part of the intentional threat model.
