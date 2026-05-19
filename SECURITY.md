# Security Policy

## Supported versions

Security fixes are backported to the most recent minor release branch.
Once a new minor ships, the previous minor receives security fixes only
for **six months**.

| Version | Status       | Security fixes until                |
|---------|--------------|-------------------------------------|
| 1.1.x   | Active       | until 1.2.0 ships, then +6 months   |
| 1.0.x   | Maintenance  | 2026-11-17 (six months past 1.1.0)  |
| < 1.0   | End of life  | not supported                       |

Patch releases (1.x.y) carry no breaking changes; upgrading from 1.x.y to
1.x.(y+1) is always safe.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for security reports.**

Two private channels, in order of preference:

1. **GitHub Security Advisories.** Open a draft advisory in the repo:
   <https://github.com/ideaconnect/idct-sftp-client/security/advisories/new>.
   This is the fastest path — it keeps the discussion in the same place
   as the fix.
2. **Email.** `security@idct.tech`. Include "idct/sftp-client" in the
   subject. Encryption with a PGP key is welcome but not required; if
   you have a public key, attach it and we'll respond in kind.

Please include in your report:

- A clear description of the vulnerability and its impact.
- Steps to reproduce, including the minimum PHP / `ext-ssh2` / libssh2
  versions you tested against.
- Whether you've published anything about the issue yet (we appreciate
  responsible disclosure but won't pressure you to keep it private).
- Whether you'd like to be credited (and the name to use) once the fix
  ships.

## Response SLA

We aim to:

- **Acknowledge** every report within **2 working days**.
- Provide a **triage decision** (accepted / needs-more-info / not a
  vulnerability) within **5 working days**.
- Ship a patched release within **30 days of acknowledgement** for
  confirmed vulnerabilities of any severity. Critical issues (RCE,
  credential exfiltration, MITM bypass) get priority and usually ship
  within a few days.

If we miss any of these targets, please follow up — the team is small
and notifications occasionally fall through.

## Scope

In scope:

- `idct/sftp-client` itself — anything under `src/`.
- The library's interaction with `ext-ssh2` and `libssh2` (e.g., URI
  construction, stream-wrapper handling, fingerprint comparisons, known-
  hosts parsing).
- Documented usage patterns in `README.md` and `docs/`.

Out of scope (handle upstream):

- Vulnerabilities in `ext-ssh2` or `libssh2` themselves.
- Vulnerabilities in PHP itself.
- Vulnerabilities in the application that *uses* this library (e.g.,
  weak password handling on the caller side).
- Issues that require an attacker to already have write access to the
  user's PHP source code or `vendor/` directory.

If you're unsure whether something is in scope, report it — we'd rather
triage than miss a real issue.

## Hardening already in place

- All ext-ssh2 calls are funnelled through one adapter
  (`src/Ssh2/Ssh2Functions.php`) that converts low-level warnings into
  typed exceptions.
- Every remote path is run through `PathValidator` before any SFTP call.
  Rejected inputs: null bytes (`\0`), CR/LF and other C0/C1 control
  characters, `.` / `..` components, paths over 4096 bytes by default.
  Absolute paths bypass the configured remote prefix (rather than
  concatenating into a nonsensical `/uploads//abs/dest`), and the
  joined result is re-validated so attackers can't smuggle traversal
  through the prefix.
- Atomic uploads are on by default (write to `.partial-{uuid}` →
  `sftp_rename` → unlink on failure), so a crashed upload doesn't leave
  callers reading a half-written file at the destination path.
- Connect supports server fingerprint pinning
  (`expectedFingerprint`) and OpenSSH-format `known_hosts` verification
  with strict-by-default unknown-host policy
  (`UnknownHostPolicy::Reject`). `TrustOnFirstUse` is opt-in and
  appends a custom `sha1-fpr` keytype entry — see the design note
  below.
- `SecurityProfile` enum (`Modern` / `Compatible` / `Legacy`) restricts
  cipher / MAC / KEX / host-key algorithms at connect time. Default
  is `Compatible` (libssh2 defaults); `Modern` locks to ChaCha20+Poly1305,
  curve25519, Ed25519, and SHA-256 ETM MACs; `Legacy` is permissive and
  emits a `notice`-level log line on every use.
- `AuthFailureRateLimiter` (opt-in via `setAuthFailureRateLimiter()`)
  applies in-process per-host exponential backoff after consecutive
  auth failures. Complements server-side fail2ban / sshguard for
  callers that catch the auth exception and re-invoke `connect()` in
  their own loop. Threshold defaults: 3 failures → 1 s base → 60 s cap.
- Passwords and key passphrases are `#[\SensitiveParameter]` everywhere
  they're passed; `Credentials::__debugInfo()` redacts them from
  `var_dump`/`print_r` output.
- A lint test (`tests/unit/LoggerRedactionLintTest.php`) statically
  scans `src/` and fails the build if the literal tokens `password` or
  `passphrase` appear in any statement that also contains a log call.
- CI runs `composer audit --no-dev --locked` on every push; the build
  fails on any advisory affecting our pinned dependencies. A separate
  SAST job runs Psalm.

## Design notes (not vulnerabilities)

Mentioned here so a "missing feature" report can be triaged as
"working as designed" rather than as a security issue:

- **TOFU appends use a custom `sha1-fpr` keytype**, not standard
  `ssh-rsa`/`ssh-ed25519` lines — `ext-ssh2` doesn't expose the raw
  host key blob, only its fingerprint, so we can't write an entry that
  `ssh(1)` would read back. OpenSSH silently skips unknown keytypes, so
  coexistence in the same file is safe.
- **The host-key fingerprint we hash for `known_hosts` is SHA-1, not
  SHA-256.** `SSH2_FINGERPRINT_SHA256` only appears in libssh2 ≥ 1.9;
  the library's floor is `ext-ssh2 >= 1.4` against libssh2 ≥ 1.10 but
  some shipping packages still build against older libssh2. The
  `sha1-fpr` keytype documents this explicitly. (The
  `expectedFingerprint` parameter to `connect()` accepts whatever
  algorithm/encoding pair the caller picks — SHA-256 hex is the
  default there.)
