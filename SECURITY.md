# Security Policy

## Supported versions

Security fixes are backported to the most recent minor release branch.
Once a new minor ships, the previous minor receives security fixes only
for **six months**.

| Version | Status       | Security fixes until                |
|---------|--------------|-------------------------------------|
| 1.0.x   | Active       | until 1.1.0 ships, then +6 months   |
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

### Transport & handshake

- All ext-ssh2 calls are funnelled through one adapter
  (`src/Ssh2/Ssh2Functions.php`) that converts low-level warnings into
  typed exceptions. This is the only `@`-suppressed boundary in the
  library — every call site above the adapter sees a real exception,
  never a silenced warning.
- When the caller supplies `timeoutSeconds`, `connect()` runs a
  TCP-level probe (`stream_socket_client()`) *before* initiating the
  SSH handshake. A dead or firewalled peer is rejected quickly with a
  `ConnectionException` instead of blocking the worker for the full
  libssh2 default timeout (which can be minutes). The probe is
  skipped when `timeoutSeconds` is unset, so legacy callers see no
  behavioural change.
- Server identity verification happens via either an explicit pinned
  fingerprint (`expectedFingerprint` parameter — algorithm/encoding
  chosen by the caller) or an OpenSSH-format `known_hosts` file. With
  neither configured the connection still completes, but it then
  relies on the network/DNS path being trustworthy. **In production,
  always set one or the other** — see the recommendations below.
- `UnknownHostPolicy::Reject` is the default for unknown hosts when
  `knownHostsFile` is set; `TrustOnFirstUse` is opt-in and appends a
  custom `sha1-fpr` keytype entry (see the design note below). A
  freshly created `known_hosts` file is `chmod 0600` so the
  fingerprint store isn't world-readable.
- `SecurityProfile` enum (`Modern` / `Compatible` / `Legacy`) restricts
  cipher / MAC / KEX / host-key algorithms at connect time. Default
  when unset is libssh2's own algorithm list; `Modern` locks to
  ChaCha20+Poly1305, curve25519, Ed25519, and SHA-256 ETM MACs;
  `Legacy` is permissive (3DES + diffie-hellman-group1 still allowed
  for ancient appliances) and emits a `notice`-level log line on every
  use so the choice is auditable.

### Credentials & authentication

- Passwords and key passphrases are marked `#[\SensitiveParameter]`
  everywhere they're passed; `Credentials::__debugInfo()` redacts the
  stored values from `var_dump` / `print_r` / error-log output.
- `CredentialsLoaderInterface` (via `setCredentialsLoader()`) re-resolves
  credentials on every `connect()`, so short-lived tokens from secret
  managers can rotate without the client holding a stale value. Mutually
  exclusive with `setCredentials()`; the loader wins.
- `AuthFailureRateLimiter` (opt-in via `setAuthFailureRateLimiter()`)
  applies in-process per-host exponential backoff after consecutive
  auth failures. Complements server-side fail2ban / sshguard for
  callers that catch the auth exception and re-invoke `connect()` in
  their own loop. Threshold defaults: 3 failures → 1 s base → 60 s cap.
- A lint test (`tests/unit/LoggerRedactionLintTest.php`) statically
  scans `src/` and fails the build if the literal tokens `password` or
  `passphrase` appear in any statement that also contains a log call.

### Paths & filesystem

- Every remote path is run through `PathValidator` before any SFTP
  call. Rejected inputs: null bytes (`\0`), CR/LF and other C0/C1
  control characters, `.` / `..` components, paths over 4096 bytes by
  default. Absolute paths bypass the configured remote prefix (rather
  than concatenating into a nonsensical `/uploads//abs/dest`), and the
  joined result is re-validated so attackers can't smuggle traversal
  through the prefix.
- `ShellSumRemoteHasher` (the shell-side checksum helper) additionally
  runs the remote path through `escapeshellarg()` before invoking
  `sha256sum`. PathValidator already rejects the bytes that would
  break shell quoting; the escape is a second line of defence so that
  *any* future weakening of PathValidator can't promote a path into a
  shell injection.
- Atomic uploads are on by default (write to `.partial-{uuid}` →
  `sftp_rename` → unlink on failure), so a crashed upload doesn't
  leave callers reading a half-written file at the destination path.
- `makeDirectory()` creates remote directories with mode `0o755`
  (historically `0o777`) — readable by group/world, writable only by
  owner. Callers needing tighter modes pass an explicit `$mode`.
- `getFileList()` filters `.` and `..` from its output by default;
  callers that *want* the dot-entries pass `includeDotEntries: true`.
  Closes a small B9-class footgun where iterating `getFileList()` and
  recursing would self-loop.

### Supply chain & build

- CI runs `composer audit --no-dev --locked` on every push; the build
  fails on any advisory affecting our pinned dependencies. A separate
  SAST job runs Psalm.
- Release tags must be GPG-signed — `.github/workflows/release.yml`
  rejects an unsigned tag and refuses to publish. The signing key
  lives on the maintainer's machine, never in the repo or CI secrets.

## Defaults that fail closed

If you don't override anything, `connect()` already picks the
conservative side of every choice:

| Setting                       | Default                                | Why                                                       |
|-------------------------------|----------------------------------------|-----------------------------------------------------------|
| `fingerprintAlgorithm`        | `Sha256`                               | SHA-1 / MD5 are accepted for legacy peers but not chosen  |
| `fingerprintEncoding`         | `Hex` (lowercase, no separators)       | Easy to compare against `ssh-keyscan` output              |
| `onUnknownHost` (with `knownHostsFile`) | `Reject`                     | Unknown host = refuse, not "trust silently"               |
| Atomic upload                 | on                                     | No half-written destinations on crash                     |
| `makeDirectory()` mode        | `0o755`                                | Writable only by owner                                    |
| `getFileList()` dot entries   | filtered out                           | Recursive walks don't self-loop                           |
| `SecurityProfile`             | unset (libssh2 default algorithm list) | Set `Modern` for greenfield deployments                   |
| `bestEffort` on directory ops | `false`                                | Errors surface immediately rather than being collected    |

## Recommendations for production callers

These are not enforced by the library — they're the configuration
choices that close the remaining gap between "compiles" and "deploys
safely."

- **Pin server identity.** Either set `expectedFingerprint` (with the
  algorithm/encoding you control) or point `knownHostsFile` at a file
  whose contents you trust. Without one of the two, the connection
  trusts whatever the network/DNS path delivers — which is fine for
  CI fixtures and unsafe for production.
- **Set `timeoutSeconds`.** Default libssh2 timeouts are minutes; in a
  worker pool that's a denial-of-service vector. 10 – 30 s is
  reasonable for most workloads.
- **Set `SecurityProfile::Modern`** for greenfield deployments. The
  default leaves algorithm negotiation to libssh2; `Modern` removes
  the legacy ciphers from the menu entirely.
- **Use `setAuthFailureRateLimiter()`** in long-running daemons that
  retry `connect()` on failure. Without it, a wrong-credential loop
  hammers the server until fail2ban catches it.
- **Use `setCredentialsLoader()`** rather than `setCredentials()` if
  you're rotating short-lived tokens or fetching from a secret store.
- **Enable checksum verification** (`setRemoteHasher()` with
  `RedownloadRemoteHasher` or `ShellSumRemoteHasher`) for transfers
  where silent corruption matters. ext-ssh2 only verifies file size,
  not bytes.

## What we explicitly don't do (by design)

Listed here so a "missing feature" report can be triaged as "out of
scope" rather than as a vulnerability:

- **No credential persistence.** Credentials live in memory for the
  lifetime of the `SftpClient` instance and are never written to disk
  by the library. If your application caches them, that's your
  application's concern.
- **No automatic key generation.** The library doesn't generate SSH
  keypairs; callers point `Credentials::withPublicKey()` at existing
  files.
- **No per-host secret encryption at rest.** `Credentials` holds
  passwords as plain strings (`#[\SensitiveParameter]` controls
  serialization, not storage). Use OS-level secret management or
  a secret store + `CredentialsLoaderInterface`.
- **No transport-layer encryption choices below libssh2.** The
  `SecurityProfile` enum maps to libssh2's `methods` parameter; we
  don't implement our own cipher selection.
- **No SFTP-server-side validation.** The library is a client only —
  it doesn't verify that the server you connect to is configured
  safely. Use `expectedFingerprint` to detect drift.

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
