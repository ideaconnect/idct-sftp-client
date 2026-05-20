# Changelog

## 1.0.0 — 2026-05-20

The 1.0 release bundles two passes of work into a single first-stable
cut:

* The **original modernization pass** (PHP 8.2+ floor, typed exception
  hierarchy, ext-ssh2 ≥ 1.4 wrapper, 100% line coverage, CI matrix) —
  bug-fix list `B1`–`B12` and security baseline `S1`–`S5`.
* The **production-grade phases** `P1`–`P11` — atomic uploads, resume,
  recursive directory operations, streaming sources/sinks, progress
  callbacks, retry policies, PSR-3 logging, known-hosts verification,
  security profiles, an opt-in checksum verification seam, and
  hardening + tooling round-outs.

The production-grade work is listed first below (newest), followed by
the [original modernization pass](#original-modernization-pass-2026-05-17).

### Follow-up pass — resolve every partially-done phase (2026-05-19)

This pass closes the named follow-up subtasks created when each partial-
done phase was first marked closed. Net result: every P1–P11 phase is
fully implemented except the explicitly out-of-scope items (Conventional
Commits enforcement, CODE_OF_CONDUCT.md, the 24h soak which needs wall-
clock time rather than code, and Packagist/GPG secret config which is
inherently maintainer-side).

P8 follow-ups:
* New `IDCT\Networking\Ssh\Security\SecurityProfile` enum (Modern /
  Compatible / Legacy). `SftpClient::connect()` gains an optional
  `?SecurityProfile $securityProfile` argument that translates to the
  `$methods` array `ssh2_connect` expects. Modern locks to
  ChaCha20+Poly1305 / curve25519 / Ed25519 / SHA-256-ETM; Compatible
  delegates to libssh2 defaults; Legacy is permissive (with a
  `notice`-level log line whenever used). Wired through the
  Ssh2FunctionsInterface.
* New `IDCT\Networking\Ssh\Auth\AuthFailureRateLimiter` — in-process
  per-host backoff after consecutive auth failures. Off by default;
  enable via `setAuthFailureRateLimiter()`. State is static, keyed by
  `host:port:user`. Defaults: 3-failure threshold, 1s base delay,
  60s cap.
* New `IDCT\Networking\Ssh\Auth\CredentialsLoaderInterface` + default
  `StaticCredentialsLoader`. `SftpClient::setCredentialsLoader()` is
  mutually exclusive with `setCredentials()`; the loader fires once
  per `connect()` so secret-store integrations can rotate credentials
  per host.

P3 follow-ups:
* New `Directory\ConflictPolicy` enum (Overwrite / Skip / Fail) wired
  into `uploadDirectory()` + `downloadDirectory()` via new
  `onConflict` parameters. Default stays Overwrite (existing pre-policy
  behaviour). Skip records the source path in the result's `skipped`
  list; Fail raises `RemoteFilesystemException` (upload) /
  `ConfigurationException` (download).
* New `Directory\SymlinkPolicy` enum (Skip / Follow) — default still
  Skip. Follow recurses through symlinked directories with inode-set
  cycle detection (`(dev, ino)` keys); a detected cycle is recorded
  in `skipped` with a `(cycle)` marker. Download-side symlink-follow
  is a documented gap (ext-ssh2 doesn't expose libssh2's per-link
  target resolution consistently).
* New best-effort mode (`$bestEffort` parameter on both methods).
  When true, per-entry failures are collected into the result's new
  `failures` field (`list<DirectoryFailure>`) instead of aborting the
  walk. New `Directory\DirectoryFailure` value object captures
  `{path, reason, exceptionClass}`.

P4 follow-up:
* Opt-in checksum verification via a pluggable
  `IDCT\Networking\Ssh\Checksum\RemoteHasherInterface`. When set via
  `SftpClient::setRemoteHasher()`, every successful upload /
  resumeUpload / download / resumeDownload computes both sides'
  digests with `hash_file()` and the hasher and throws
  `TransferException` on mismatch.
* Two stock implementations:
  - `ShellSumRemoteHasher` — runs the server's `sha256sum` (or any
    configured sum binary) via `ssh2_exec`. Requires shell access.
  - `RedownloadRemoteHasher` — pulls the file back through
    `downloadStream` and hashes it locally. Works on lockdown-mode
    SFTP servers without shell access; doubles transfer time.
* New `Ssh2FunctionsInterface::exec()` underpins the shell variant.

P11 follow-ups:
* Eris property-based path tests
  (`tests/unit/Path/PathValidatorPropertyTest.php`) complement the
  hand-rolled T1-T6 matrix. 6 properties prove the
  "either accepts safely or rejects with `InvalidPathException`, never
  crashes" contract holds for random byte strings.
* Multi-server matrix: `tests/functional/docker-compose.yml` now also
  runs `linuxserver/openssh-server` (OpenSSH 9.x) on `127.0.0.1:2223`
  alongside the existing atmoz/sftp on 2222. Behat is parameterised
  via `SFTP_HOST` / `SFTP_PORT` / `SFTP_USER` / `SFTP_PASS` env vars.
  CI's `functional` job is now a matrix `{php × {atmoz, openssh}}`.
* New minio S3 source for the upload-from-S3-stream scenario
  (`tests/functional/features/s3-stream.feature`). A one-shot
  `minio-init` container creates a public bucket and seeds a payload;
  the scenario `fopen`s the HTTP URL into `uploadStream` and verifies
  byte-identity. No AWS SDK dependency — plain HTTP.
* New toxiproxy fault-injection scenarios
  (`tests/functional/features/fault-injection.feature`, tagged
  `@slow @toxiproxy`): latency injection + bandwidth cap. The proxy
  is configured per-scenario via toxiproxy's HTTP control API.
* New soak script `tests/soak/soak.php` + manual-trigger workflow
  `.github/workflows/soak.yml`. Defaults to a 15-minute smoke (the
  full plan-mandated 24h target needs a self-hosted runner because of
  GitHub's 6h hosted-job ceiling). Records JSON summary
  (`{cycles, bytes, failures, peak_memory}`) and uploads as a CI
  artifact.

P10 follow-ups:
* New `.github/workflows/release.yml` — triggers on `vX.Y.Z` tags,
  runs the full QA gate, GPG-verifies the tag (rejects unsigned),
  extracts the matching CHANGELOG section as the release body, and
  pings the Packagist webhook when `PACKAGIST_TOKEN` is configured.
  GPG signing and Packagist token are maintainer-side concerns
  documented in [SECURITY.md](SECURITY.md) and the workflow comments
  respectively.
* New `.github/workflows/sast.yml` running Psalm in taint-analysis
  mode. Psalm is downloaded as a standalone phar rather than a
  composer dev-dep — Psalm 5.x's hard `nikic/php-parser ^4.x`
  constraint conflicts with PHPUnit 11's `^5.x`. Checked-in
  `psalm.xml.dist` keeps the config deterministic.
* Conventional Commits enforcement remains deferred (opinionated
  commit-style mandate; the CHANGELOG continues to be hand-written).
  CODE_OF_CONDUCT.md remains deliberately not shipped per maintainer
  preference.

### P10 — Operational maturity (partial — contributor-facing files)

* New [CONTRIBUTING.md](CONTRIBUTING.md): local setup, the three test
  layers (`composer qa` / `composer behat` / `composer infection`),
  coverage + mutation gates, PR checklist, the "no comments unless the
  WHY is non-obvious" rule, sign-off.
* New [COMPATIBILITY.md](COMPATIBILITY.md): SemVer policy spelled out.
  Defines the covered surface (interfaces, public concrete classes,
  enums, named exceptions, public readonly DTO fields) and the
  internal surface (private methods, exception message text, Ssh2
  adapter, lint / coverage / mutation config, Behat suite). Includes
  the deprecation policy (minor-bump deprecation, at least one minor
  cycle before removal in the next major) and the ext-ssh2 / PHP
  floor rules.
* New `.github/ISSUE_TEMPLATE/`:
  - `bug_report.yml` — structured fields for library / PHP / ext-ssh2
    / libssh2 version + SFTP server + minimal repro.
  - `feature_request.yml` — use case first, proposed API second,
    alternatives considered, willing-to-PR dropdown.
  - `config.yml` — disables blank issues, routes security to the
    private advisory, points "how do I..." questions at Discussions.
* New `.github/PULL_REQUEST_TEMPLATE.md` — concise checklist (QA,
  Behat, coverage, mutation gates, CHANGELOG entry, COMPATIBILITY.md
  update if the surface changed, regression test for bug fixes).
* New `.github/dependabot.yml` — weekly composer + github-actions
  groups, dev-dep minor/patch bundled to reduce PR noise.
* Already shipped by P8 (not redone here): SECURITY.md, `composer
  audit` step in CI.
* Deliberately NOT shipping a `CODE_OF_CONDUCT.md` — maintainer
  preference. (Recorded in the user-memory so it doesn't get auto-
  re-added if a future tooling pass scans for "standard project
  files".)
* Deferred to named follow-up subtasks under MYID-4:
  - CodeQL workflow (GitHub CodeQL doesn't officially support PHP — a
    Psalm-as-SAST or third-party scanner is the right substitute, but
    that's a tooling choice rather than a file drop-in).
  - Release automation (`release-please` + `release.yml`) — needs
    Packagist webhook config, repo secrets, and the plan's GPG
    release-signing setup. Multi-week landing, deserves its own task.
  - Conventional Commits enforcement — opinionated commit-style
    mandate; left to maintainer preference.

### P11 — Test additions (partial — mutation testing only)

* **Infection mutation testing is now enforced in CI.** New
  `.github/workflows/ci.yml` job `mutation` (PHP 8.2, post-unit) runs
  `vendor/bin/infection` with `--logger-github` and gates the build on
  the thresholds in `infection.json5`:
  - `minMsi: 85` (current baseline ~86%)
  - `minCoveredMsi: 85` (current baseline ~87%)
  Both gates are 2pp under the actual baseline — strict enough that any
  real test-gap mutant trips the build, lenient enough not to chase
  harmless mutants (operand-reordering on exception messages,
  redundant `(string)` casts) into brittle exact-text assertions.
* `infection.json5` excludes `src/Ssh2/Ssh2Functions.php` — that
  adapter is exercised only by Behat, so unit-suite mutation analysis
  would mark every mutant as survived without signal.
* New `composer infection` script for local parity with CI (runs with
  `XDEBUG_MODE=coverage` + 4 threads).
* The remaining P11 items (multi-server matrix with OpenSSH 9.x /
  ProFTPD, large-file + 24h soak nightly, toxiproxy fault injection,
  property-based path tests via Eris) are tracked as named follow-up
  subtasks under MYID-4 — each carries its own scope, acceptance, and
  reopening criteria. The 500 MB nightly upload task created earlier
  is the first slice of the large-file work.

### P8 — Security hardening (round 2, partial)

* **Known-hosts file support.** `SftpClient::connect()` gains two new
  parameters:
  - `?string $knownHostsFile` — path to an OpenSSH-format
    `known_hosts` file. When set, the server's host key is verified
    against the file before authentication runs.
  - `UnknownHostPolicy $onUnknownHost` — what to do when the server's
    host isn't in the file. `Reject` (default) refuses the connection;
    `TrustOnFirstUse` appends the fingerprint and proceeds.
  Mismatch (host present but with a different key) always refuses the
  connection — `TrustOnFirstUse` does NOT override mismatch.
* New `src/KnownHosts/` namespace: `KnownHostsFile` (parser +
  verifier + appender), `HostKeyDecision` enum
  (`Trusted | Mismatch | NoEntries`), `UnknownHostPolicy` enum.
* Parser supports plain hostspecs, port-qualified `[host]:port`,
  hashed `|1|salt|hash`, and the library's own TOFU keytype
  `sha1-fpr`. Negation, wildcard, `@cert-authority`, and `@revoked`
  entries are skipped (silent — matches OpenSSH's tolerant parser).
* SHA-1 (not SHA-256) is the comparison algorithm:
  `SSH2_FINGERPRINT_SHA256` only appears in libssh2 1.9+, and the
  library ships against `ext-ssh2 >= 1.4`. SHA-1 is still acceptable
  for fingerprint comparison and is exactly the algorithm older
  OpenSSH clients (and `ssh-keygen -E sha1`) use. Standard
  `ssh-rsa`/`ssh-ed25519`/etc. entries are matched by computing SHA-1
  of the decoded key blob.
* TOFU appends use a custom `sha1-fpr` keytype (with the lowercase
  hex fingerprint in the keydata field) rather than a standard
  `ssh-rsa AAAA…` line, because `ext-ssh2` exposes only the
  fingerprint — not the raw host key blob — so we can't write a line
  `ssh(1)` would read back. OpenSSH silently skips unknown keytypes
  when reading the file, so cohabiting with `ssh(1)`'s own entries is
  safe.
* New `SECURITY.md` documents the disclosure policy (GHSA preferred,
  `security@idct.tech` fallback), supported-versions matrix, SLA
  targets (2/5/30 days for ack / triage / fix), and the scope.
* `.github/workflows/ci.yml` runs `composer audit --no-dev --locked`
  on every push; the build fails on any advisory matching the pinned
  dependencies.
* Tests: 21 unit tests for the parser/verifier/appender in
  `tests/unit/KnownHosts/KnownHostsFileTest.php`; 6 connect-integration
  tests in `tests/unit/KnownHosts/ConnectKnownHostsTest.php`; 4 Behat
  scenarios in `known-hosts.feature` (TOFU happy path, repeat-connect
  doesn't double-append, Reject refuses unknown host, tampered file
  surfaces mismatch).
* Deferred to named follow-up subtasks under MYID-4 (will be created
  alongside this CHANGELOG entry):
  - **SecurityProfile enum** (Modern / Compatible / Legacy) + cipher
    / MAC / KEX allow-list — useful but libssh2's defaults are
    reasonable for the common case; payoff is smaller than known-hosts.
  - **Auth-failure rate limit** — the existing retry policy already
    hard-blocks auth-retry per its never-retry list, so the marginal
    value is bounded. Will revisit if a real incident surfaces.
  - **`CredentialsLoaderInterface`** — ergonomic, not security:
    `setCredentials($loader->load($host))` covers the same shape for
    now.
* While fixing the Behat suite, the `the remote directory "..." is
  empty` step was updated to fall back to `removeDirectoryTree()` when
  the entry is a directory (the previous `remove()`-only loop
  accumulated leftover trees across runs).

### P3 — Recursive directory operations

* New `src/Directory/` namespace ships four small value types:
  - `EntryType` enum: `File | Directory | Symlink | Other` (sockets / FIFOs / devices fall into `Other`).
  - `RemoteEntry` readonly: `{path, type, ?size}`.
  - `UploadResult` / `DownloadResult` readonly: `{filesTransferred, bytesTransferred, skipped}`.
* New `SftpClient::walk(string $remoteDir): iterable<RemoteEntry>` — post-order generator (children before their parent). Useful for `rm -rf`, archive backup, audits.
* New `SftpClient::uploadDirectory(string $localDir, string $remoteDir, bool $createRemoteDir = true, ?ProgressListenerInterface)`: recursive upload. Walks the local tree via `RecursiveIteratorIterator` (top-down so dirs land before files), `mkdir`s each subdir, and delegates per-file transfer to `upload()` — so atomic write, retry, file-size verification, and progress emission all apply per file. Symlinks under the local tree are skipped and listed in `UploadResult::$skipped`.
* New `SftpClient::downloadDirectory(string $remoteDir, string $localDir, ?ProgressListenerInterface): DownloadResult` — mirror image. Creates the local destination if missing; delegates per-file to `download()`. Remote symlinks are skipped.
* New `SftpClient::removeDirectoryTree(string $remoteDir): self` — post-order recursion. `sftpUnlink`s files and symlinks, `sftpRmdir`s empty directories, removes `$remoteDir` itself last. Server permission failures surface as `RemoteFilesystemException` with the offending path.
* Internal: `entryType()` classifies remote paths via `lstat()` on the SFTP stream wrapper (mode bits) with a fallback to `sftpStat()` for older libssh2 builds that don't expose lstat through the URL stat path.
* Tests: 22 new unit tests in `tests/unit/DirectoryOperationsTest.php` cover walk ordering, symlink classification, the lstat→sftpStat fallback chain, nested round-trips (≥ 3 levels with mixed empty / non-empty dirs), per-method failure paths. 3 small VO tests in `tests/unit/Directory/ValueObjectsTest.php`. 2 Behat scenarios in `directory-ops.feature` round-trip a nested tree and exercise `removeDirectoryTree` against the live atmoz/sftp container.
* Plan deltas (deferred to the follow-up pass on 2026-05-19, see top of
  this changelog):
  - **Follow-symlinks-with-cycle-detection.** Ship default is "skip symlinks" only; the opt-in follow mode with inode tracking is deferred.
  - **Conflict modes (skip / fail).** Ships overwrite-only (atomic rename does this naturally for files; `mkdir` is idempotent).
  - **Best-effort partial-failure mode.** Ships abort-on-first-failure (the plan's default); the best-effort variant that returns the list of failures is deferred.

### P6 — Streaming sources/sinks & progress callbacks

* `ProgressListenerInterface` (declared in P1, unwired until now) is wired
  into every SFTP transfer path: `upload()`, `download()`, `resumeUpload()`,
  `resumeDownload()`, `uploadStream()`, `downloadStream()`. Pass an
  implementation via the new optional `?ProgressListenerInterface $progress`
  argument. SCP transfers are NOT wired — ext-ssh2 doesn't expose
  libssh2's per-chunk callbacks for `scp_send` / `scp_recv`.
* Lifecycle contract enforced by `SftpClient`:
  `started($operation, $totalBytes)` → zero or more `progress($bytesDone)` →
  exactly one of `completed($bytesDone)` or `failed(\Throwable)`. The
  terminator covers the *whole* operation, so atomic upload's rename
  failure surfaces as `failed()` rather than a stray `completed()`.
* New `chunkSize` constructor argument + `setChunkSize(int)` /
  `getChunkSize()`. Defaults to `SftpClient::DEFAULT_CHUNK_SIZE` (1 MiB);
  controls per-chunk `fread`/`fwrite` size and progress emission cadence.
  Constructor / setter throw `ConfigurationException` on `< 1`.
* New `uploadStream(resource $stream, string $remote, ?int $expectedSize,
  ?ProgressListenerInterface)` and `downloadStream(string $remote,
  resource $stream, ?ProgressListenerInterface): int`. uploadStream
  honors the atomic-uploads flag (writes to `.partial-{uuid}`, then
  renames); downloadStream returns the byte count written to the sink.
  Both throw `ConfigurationException` if `$stream` is not an open
  resource; uploadStream also validates `$expectedSize >= 0`.
* Internal: `stream_copy_to_stream()` calls in all transfer paths
  replaced by a new chunked helper `copyWithProgress()` that emits
  `progress($bytesDone)` after each successful chunk write. Avoids
  `feof()` (unreliable on some libssh2 stream wrappers) — uses
  `fread() === ''` as the EOF signal.
* `statSize()` now returns `int<0, max>|null` so progress listeners get
  a type-safe non-negative total.
* Tests: 22 new unit tests in `tests/unit/StreamingAndProgressTest.php`
  (lifecycle on success/failure for upload, download, resume*, stream
  variants; chunkSize cadence; validation guards). 3 new Behat scenarios
  in `streaming-progress.feature` exercise `uploadStream` from
  `php://memory`, `downloadStream` into an in-memory sink, and the
  end-to-end progress lifecycle.
* Plan deviation noted: the §P6 plan also suggested a minio (S3)
  docker-compose scenario for the "upload from S3 stream" round-trip.
  Skipped — adds a whole second container and an AWS SDK dep for
  marginal extra coverage over the in-memory stream test, which already
  proves any PHP stream resource flows through `uploadStream`. Can
  revisit if a real S3 acceptance environment surfaces.

### P4 — Atomic transfers & resume

* **Atomic uploads, default on.** `SftpClient::upload()` now writes to a
  hidden `{dir}/.{basename}.partial-{8hex}` sibling and atomically renames
  onto the final path on success. On failure, the partial is best-effort
  `sftpUnlink`'d so dropped uploads don't pile up. Toggle off via
  `disableAtomicUploads()` for servers that reject overwrite-on-rename;
  query via `getAtomicUploads()`. Constructor signature gains a fourth
  positional arg `bool $atomicUploads = true` (existing call sites with
  fewer args are unaffected). SCP uploads are NOT atomic — SCP is a
  one-shot push with no rename step.
* **`resumeUpload(string $local, string $remote, ?int $offset = null)`.**
  Appends to a deterministic `{dir}/.{basename}.resume` sibling using
  libssh2's `r+b` + seek (the `ab` wrapper accepts open but its `fwrite`
  returns false). When `$offset` is null, the client stats the partial
  and resumes from its current size; a caller-supplied offset overrides
  the auto-detect. Failures preserve the partial so the next call picks
  up where this one left off (contrast: atomic upload unlinks the
  partial on failure).
* **`resumeDownload(string $remote, string $local, ?int $offset = null)`.**
  Appends to an existing local file; when offset is null, stats the local
  file to derive the resume point. Returns successfully without re-opening
  the remote stream when the local size already equals the remote — safe
  to call after a previous successful resume.
* Argument validation on both resume methods: negative offsets and
  offsets beyond the source size raise `ConfigurationException`.
* Tests: 28 new unit tests in `tests/unit/AtomicUploadAndResumeTest.php`
  covering happy paths, partial cleanup, rename failure, size mismatch,
  offset auto-detection, validation, no-op-on-completed, plus a
  reflection-based test for the `seekOrThrow` defensive guard. 4 new
  Behat scenarios in `atomic-and-resume.feature` round-trip atomic
  uploads, resume uploads from a server-side partial, resume downloads
  into a partial local file, and the noop-on-completed case against the
  live atmoz/sftp container.
* **Checksum verification (plan §P4) deferred to a follow-up.** The
  proposed flow needs `ssh2_exec("sha256sum ...")` to verify on the
  server side, which assumes shell access and the binary on PATH —
  environment-dependent enough that a half-implementation would be worse
  than what we ship today (size verification, atomic write, resume).
  Will revisit when there's a concrete acceptance environment for the
  exec path.

### P1 (revised) — single-package public surface + domain-grouped layout

* The standalone `idct/sftp-client-contracts` package is gone. Everything
  it carried — `SftpClientInterface`, `CredentialsInterface`, the
  `AuthMode` / `FingerprintAlgorithm` / `FingerprintEncoding` enums,
  `RetryPolicyInterface`, `ProgressListenerInterface`, `PathValidator`,
  `InvalidPathException` — now lives in `src/` alongside the rest of the
  library. A separate package was overkill for a single-purpose library;
  this collapses the maintenance surface.
* **Source layout reorganised into per-domain sub-namespaces:**

  | Old FQN | New FQN |
  |---|---|
  | `IDCT\Networking\Ssh\AuthMode` | `IDCT\Networking\Ssh\Auth\AuthMode` |
  | `IDCT\Networking\Ssh\Credentials` | `IDCT\Networking\Ssh\Auth\Credentials` |
  | `IDCT\Networking\Ssh\CredentialsInterface` | `IDCT\Networking\Ssh\Auth\CredentialsInterface` |
  | `IDCT\Networking\Ssh\FingerprintAlgorithm` | `IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm` |
  | `IDCT\Networking\Ssh\FingerprintEncoding` | `IDCT\Networking\Ssh\HostKey\FingerprintEncoding` |
  | `IDCT\Networking\Ssh\RetryPolicyInterface` | `IDCT\Networking\Ssh\Retry\RetryPolicyInterface` |
  | `IDCT\Networking\Ssh\ExponentialBackoffRetryPolicy` | `IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy` |
  | `IDCT\Networking\Ssh\NoRetryPolicy` | `IDCT\Networking\Ssh\Retry\NoRetryPolicy` |
  | `IDCT\Networking\Ssh\PathValidator` | `IDCT\Networking\Ssh\Path\PathValidator` |
  | `IDCT\Networking\Ssh\ProgressListenerInterface` | `IDCT\Networking\Ssh\Progress\ProgressListenerInterface` |
  | `IDCT\Networking\Ssh\Ssh2Functions` | `IDCT\Networking\Ssh\Ssh2\Ssh2Functions` |
  | `IDCT\Networking\Ssh\Ssh2FunctionsInterface` | `IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface` |

  `SftpClient`, `SftpClientInterface`, and everything under
  `IDCT\Networking\Ssh\Exception\` keep their FQNs. The single-root
  exception hierarchy stays visually grouped in one directory so the
  `SshException` parent is obvious at a glance.

  Consumer impact: update `use` statements for any class you reference
  by FQN (mechanical search-and-replace using the table above). Behaviour
  is unchanged.
* Marker exception interfaces (`SshExceptionInterface`,
  `AuthenticationExceptionInterface`, `ConfigurationExceptionInterface`,
  `ConnectionExceptionInterface`, `RemoteFilesystemExceptionInterface`,
  `TransferExceptionInterface`) are **removed**. Consumers should catch by
  the concrete classes instead — every library exception now extends a
  single root, `SshException`, so `catch (SshException $e)` is the
  one-liner to catch anything this library throws. The concrete leaves
  (`AuthenticationException`, `ConfigurationException`,
  `ConnectionException`, `RemoteFilesystemException`, `TransferException`,
  `InvalidPathException`) are unchanged in name and FQN.
* `InvalidPathException` now extends `ConfigurationException` (not
  `\InvalidArgumentException`) so the single-parent rule holds end-to-end.
  `catch (ConfigurationException $e)` still catches it; the only behaviour
  loss is that `$e instanceof \InvalidArgumentException` is now `false` —
  a very narrow case in practice.
* The `repositories` entry pointing at `contracts/` is removed from
  `composer.json`, as is the `idct/sftp-client-contracts` requirement.
  `composer.lock` is regenerated.
* `.github/workflows/contracts-split.yml` is deleted — no separate repo to
  push to anymore.
* If you (a) implemented `SftpClientInterface` in your own code and (b)
  caught exceptions by marker interface, the only edit required is
  swapping the marker name for the concrete name (`AuthenticationException`,
  etc.). If you only used the package as a consumer, nothing changes.

### P5 — Retry policy & connection lifecycle

* `connect()`, `upload()`, `download()`, `scpUpload()`, `scpDownload()` now
  go through a configurable retry policy. Filesystem ops (`remove`,
  `rename`, `makeDirectory`, `removeDirectory`, etc.) deliberately do
  **not** auto-retry — those failures are usually permanent (the file
  isn't there, the rename collision is real) and retrying masks bugs.
* Two stock policies in `src/`:
  - `ExponentialBackoffRetryPolicy` (the new default): 5 retries, 200 ms
    base, 30 s cap, ±30% multiplicative jitter. Exposes its parameters as
    readonly constructor arguments for tuning.
  - `NoRetryPolicy`: returns 0 immediately for every call — restores the
    pre-P5 single-attempt behaviour for callers that want it.
* `RetryPolicyInterface` (declared in P1) is now wired.
* `SftpClient::setRetryPolicy()` / `getRetryPolicy()` added to the
  interface. Constructor accepts an optional third arg
  (`new SftpClient($verifyFileSize, $ssh2, $retryPolicy)`).
* **Never-retry hard rules** (enforced by `SftpClient` regardless of
  policy): `AuthenticationException` (retrying a rejected password is how
  IP bans get earned), `ConfigurationException`, `InvalidPathException`.
* **Retryable exceptions**: `ConnectionException` always; `TransferException`
  only when its message starts with one of a small allowlist of clearly
  transient fragments (`Failed to copy`, `Unable to open remote`,
  `Could not SCP-download`, `Could not SCP-upload`).
* **Lazy reconnect**: when retry catches an error and a session is
  established, the client calls `ping()`; if ping reports the session
  dead, `doConnect()` runs once (bypassing the retry wrapper to avoid
  recursion) before the next attempt. Stored connect args (host, port,
  timeout, fingerprint, algorithm, encoding) are reused, so users get
  transparent re-establishment after transient network failures.
* New `SftpClient::ping(): bool` — cheap liveness probe (`ssh2_sftp_stat`
  on `/`). Contract: never throws. Use as a keepalive or to detect dead
  sessions in your own code.
* Idle timeout + true circuit breaker explicitly **deferred** — short PHP
  request lifecycle makes idle less relevant, and the policy's
  `maxRetries` cap acts as a simple circuit guard.

### P7 — PSR-3 logger integration

* `SftpClient` was already `LoggerAwareInterface`; now it actually calls
  the logger. Default is still `NullLogger`, so installing this change is
  invisible until you `setLogger(...)`.
* Log points / levels:
  - `connect()` attempt + ok (`info`); transport failure, fingerprint
    failures, SFTP-subsystem failure (`error`).
  - Auth success (`info`), auth rejection (`notice`).
  - `download` / `upload` start (`debug`), end (`info`, with `bytes` +
    `duration_ms`).
  - `scpDownload` / `scpUpload` start (`debug`), end (`info`, with
    `duration_ms`).
  - `remove` / `rename` / `makeDirectory` / `removeDirectory` (`debug`).
  - `close()` (`debug`); unexpected disconnect-exception (`warning`).
* Every record carries a base context: `correlation_id` (16-char hex,
  fresh per `connect()`, cleared on `close()`), `host`, `port`. Use it to
  group operations in log aggregation.
* New `setLogContext(array $context): self` merges caller-supplied static
  context (e.g. `request_id`, `tenant_id`) into every record. The keys
  `correlation_id`, `host`, and `port` are reserved and silently stripped
  from caller input.
* Sensitive-value guard: a new lint test
  (`tests/unit/LoggerRedactionLintTest.php`) scans every file in `src/`
  and fails the build if any statement that contains a log call also
  contains the literal tokens `password` or `passphrase`. Conservative —
  false positives possible, but the cost of a real leak is high enough to
  justify them.
* `composer.json` `suggest:` advertises `monolog/monolog` as the typical
  consumer-side plug-in.

### P1 (original) — companion contracts package (superseded above)

* (Originally shipped a standalone `idct/sftp-client-contracts` package
  under `contracts/`. Reverted in the revision entry at the top of this
  release — the interfaces / enums / `PathValidator` now live in `src/`
  alongside the implementation, and the marker exception interfaces are
  removed in favour of a single concrete `SshException` parent.)
* **Behavioural shift (internal, still in effect):**
  `Credentials::authorizeSshConnection()` moved to `SftpClient::authorize()`
  (private) so `CredentialsInterface` stays pure-data. If you were calling
  `Credentials::authorizeSshConnection()` directly (you almost certainly
  weren't — it took an ext-ssh2 resource), that's gone.

### P2 — Path safety & input validation

* New `IDCT\Networking\Ssh\PathValidator`. Public API:
  - `validateRemotePath(string $path, bool $allowAbsolute = true, int $maxLength = 4096): string`
  - `joinRemote(string $prefix, string $path): string`
* Every `SftpClient` method that takes a remote path now validates it
  **before** any SFTP I/O: `download`, `upload`, `scpDownload`, `scpUpload`,
  `remove`, `rename`, `getFileList`, `stat`, `makeDirectory`,
  `removeDirectory`, `fileExists`.
* Rejected inputs throw `IDCT\Networking\Ssh\Exception\InvalidPathException`
  (extends `ConfigurationException`, which in turn extends `SshException`,
  so `catch (SshException $e)` or `catch (ConfigurationException $e)` both
  pick it up). Rejection rules:
  - empty string
  - any null byte (`\0`)
  - any CR/LF (`\r`/`\n`) or other C0/DEL control character
  - any path component equal to `.` or `..` (traversal)
  - paths longer than 4096 bytes by default (configurable per call)
  - if `allowAbsolute` is false: paths starting with `/`
* **Breaking-ish behaviour change (T6 in the plan):** absolute remote
  paths now *bypass* the configured remote prefix instead of being
  concatenated. Before P2, `setRemotePrefix('/uploads/'); upload($f, '/abs/dest')`
  silently produced the nonsensical path `/uploads//abs/dest`. After P2,
  the absolute path is honoured as-is (`/abs/dest`) and the prefix is
  ignored. Callers that were unknowingly relying on the broken behaviour
  will see writes land in a different place — review your prefix usage if
  you mix relative and absolute remote names. Relative paths are
  unaffected.

### Original modernization pass (2026-05-17)

The modernization milestone (closed internally on 2026-05-17, rolled
into 1.0.0). PHP 8.2+ floor, full type coverage, typed exception
hierarchy, 100% unit-test line coverage, Behat integration tests against
a dockerised SFTP fixture, GitHub Actions CI on PHP 8.2/8.3/8.4.

The bug-fix matrix (`B1`–`B12`) and security baseline (`S1`–`S5`)
referenced throughout the entries below are the original modernization
identifiers tracked under MYID-4 in Asana.

#### Breaking changes
* PHP `>=8.2` required (was 5.4).
* `ext-ssh2 >=1.4` required (was 0.12).
* `AuthMode` is now a backed `enum`: `AuthMode::Password`, `AuthMode::PublicKey`,
  `AuthMode::Both`, `AuthMode::None`. Old `AuthMode::PASSWORD` etc. removed.
* `Credentials` is `final readonly`; construct via the named factories
  (`withPassword`, `withPublicKey`, `withBoth`, `withNone`). Property setters
  are gone.
* All thrown exceptions are now subclasses of `IDCT\Networking\Ssh\Exception\SshException`
  (a `RuntimeException`). Bare `\Exception` is no longer thrown anywhere.
* `connect()` signature extended with `?int $timeoutSeconds`,
  `?string $expectedFingerprint`, `FingerprintAlgorithm $fingerprintAlgorithm`,
  `FingerprintEncoding $fingerprintEncoding`. Existing callers passing only
  `$host` / `$port` continue to work.
* `getFileList()` now filters `.` and `..` by default. Pass
  `includeDotEntries: true` for the old behaviour.

#### Bug fixes
* **B1** `download()` "different file size" message no longer references an
  undefined `$localFilePath` variable.
* **B2** `Credentials::authorizeSshConnection()` handles every `AuthMode` (no
  more implicit-`null` fall-through).
* **B3** `AuthMode::Both` now requires BOTH legs to succeed; pubkey failures
  are no longer silently swallowed.
* **B4** SFTP URI building uses `intval($sftp)` consistently — works under
  PHP 8 + ext-ssh2 1.4 without `TypeError` and without "Resource id #N" URIs.
* **B5** `download()`/`upload()` use `stream_copy_to_stream` inside `try/finally`,
  so file descriptors are never leaked on the error path.
* **B6** `rename()` applies the remote prefix to BOTH source and destination.
* **B7** Removed `return $this;` from constructors (dead code).
* **B8** `setUsername(null)` no longer triggers PHP 8.1+ `strlen(null)` deprecation.
* **B9** `getFileList()` uses `!== false` so a file literally named `"0"` doesn't
  exit the loop early.
* **B10** `close()` calls `ssh2_disconnect()` instead of the broken
  `ssh2_exec($conn, 'logout')` pattern (which leaked channels and never
  actually disconnected).
* **B11** `getFileList()`/`download()`/`upload()` close handles in `finally`
  blocks — no leaks on exception.
* **B12** `Credentials` validation messages now name the actual mode the user
  selected, not always "BOTH mode".

#### Security hardening
* **S1** `connect()` accepts `expectedFingerprint` + algorithm/encoding enums;
  a mismatch immediately disconnects before authentication.
* **S2** Adapter `Ssh2Functions` is the single `@`-suppressed boundary; the
  wrapper layer surfaces typed exceptions instead of raw warnings.
* **S3** Password and passphrase parameters marked `#[\SensitiveParameter]`;
  `Credentials::__debugInfo()` redacts the stored values from `var_dump` /
  `print_r` / error-log output.
* **S4** `makeDirectory()` default mode dropped from `0777` to `0755`.
* **S5** `connect()` accepts `timeoutSeconds` and probes via
  `stream_socket_client()` before initiating the SSH handshake.

#### Tooling
* PHPStan level `max` (level 10) on `src/` with strict rules.
* PHPUnit 11 / 12 with 100% line coverage gate (`tests/bin/check-coverage.php`).
* Behat 3 functional suite against `atmoz/sftp` docker fixture.
* Infection 0.29 mutation testing (`min-msi=85`, `min-covered-msi=95`).
* PHP-CS-Fixer 3 with `@PER-CS2.0` + `@PHP82Migration`.
* Rector 2 with PHP 8.2 level set.
* GitHub Actions matrix across PHP 8.2 / 8.3 / 8.4.

## 0.4.0 — 2018-06-04 [Release Candidate]

* Changed CHANGELOG format to Markdown.
* Added README.md.
* Removed `integration-tests` folder. Added usage descriptions in the README.md.
* Dropped support for php 5.3.x

## 0.3.2 — 2017-03-26

* Added file size verification, fixed prefixes usage, added directory management
  methods, added `fileExists` method.

## 0.3.0 — 2017-03-22

* Changed the behavior of methods as a workaround for PHP SSH2 bug
  https://bugs.php.net/bug.php?id=71376
  Restored previous behavior with `intval` of SFTP Resource Handle.
* Merged PR #6 by `pedrofornaza`.
* Initialized tests scope: with TODOs.

## 0.2.0 — 2017-02-09

* Changed the behavior of methods as a workaround for PHP SSH2 bug
  https://bugs.php.net/bug.php?id=71376

## 0.1.0 — 2014-08-16

* Packagist support.
* Added changelog.rst
