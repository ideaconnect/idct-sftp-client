# AGENTS.md

Onboarding notes for AI agents (and humans) picking up work on this repo.

## Where the work lives

**Active backlog: Asana, under `MYID-4` ("Release idct-sftp-client v1.0")**
GID `1214894683655126` — [open in Asana](https://app.asana.com/1/1214897106264347/project/1214894683655121/task/1214894683655126).

The 1.1 line was developed as a sequence of phases (P1–P12) each tracked
as a subtask under MYID-4. By the time you're reading this every P1–P11
phase is shipped (see [CHANGELOG.md](CHANGELOG.md) for what landed when);
P12 (richer docs / cookbook / API reference on GitHub Pages) remains the
only open phase.

If you have the Asana MCP wired up, prefer fetching the subtask list via
`search_tasks` / `get_task task_id=1214894683655126` over guessing — the
tasks are the live status of what's done, deferred, or in flight.

Phase summary (history; not a roadmap):

| Phase | What                                             |
|------:|--------------------------------------------------|
| P1    | Public contract surface (interfaces + single SshException root) |
| P2    | Path safety & input validation (PathValidator threat matrix T1–T6) |
| P3    | Recursive directory operations (walk / upload / download / removeTree) |
| P4    | Atomic transfers & resume                        |
| P5    | Retry policy, lazy reconnect, ping()             |
| P6    | Streaming sources/sinks & progress callbacks     |
| P7    | PSR-3 logger integration + redaction lint        |
| P8    | Security hardening (known_hosts, SecurityProfile, AuthFailureRateLimiter, CredentialsLoader) |
| P10   | Operational maturity (CONTRIBUTING, COMPATIBILITY, issue/PR templates, dependabot, release.yml) |
| P11   | Test additions (Infection in CI; multi-server matrix; toxiproxy fault injection; large-file soak) |
| P12   | Documentation (cookbook, troubleshooting, perf) — **open** |

### Explicit non-goals (don't propose without reopening the discussion)

| Want                              | Why it's out of scope                                                                    |
|-----------------------------------|------------------------------------------------------------------------------------------|
| Async / event-loop transfers      | Separate package `idct/sftp-client-async` (amphp or revolt) — different concurrency model |
| Symfony bundle / Laravel provider | Separate `idct/sftp-client-bundle` / `idct/sftp-client-laravel`                          |
| OpenTelemetry tracing             | Decorate the PSR-3 logger from P7; downstream concern                                    |
| Connection pooling                | Real demand is rare and adds significant state complexity — document create-use-close    |
| FTP / FTPS support                | Different protocol family — different library                                            |
| GUI / CLI tool                    | This is a library                                                                        |
| Pure-PHP backend (phpseclib)      | Tried during P1; reverted. Reopen only if ext-ssh2 itself becomes unmaintained           |
| `CODE_OF_CONDUCT.md`              | Maintainer preference; do not add                                                        |

## How the repo got here

The 0.x line was a thin wrapper around `ext-ssh2` with bare `\Exception`
throws, untyped state, and a `close()` that ran `ssh2_exec($conn, 'logout')`
(never disconnected; leaked the channel). 1.0 was a ground-up rewrite —
typed exceptions, PHP 8.2+, `ext-ssh2 >= 1.4`, full test coverage —
documented in [CHANGELOG.md](CHANGELOG.md) under "1.0.0 — 2026-05-17".

### Four reality checks worth knowing before touching the ext-ssh2 layer

These bit during the 1.0 rewrite. Read before changing
[`src/Ssh2/Ssh2Functions.php`](src/Ssh2/Ssh2Functions.php) or
[`tests/stubs/ssh2.stub.php`](tests/stubs/ssh2.stub.php):

1. **ext-ssh2 1.4.x still returns PHP `resource`s, not opaque objects.**
   `var_dump(ssh2_connect(...))` shows `resource(SSH2 Session)`. The
   `intval($sftp)` workaround in `sftpStreamUri()` is correct under the
   current regime AND a hypothetical future opaque-object regime — keep it.
2. **PHPStan 2.x's `stubFiles:` does not override bundled JetBrains stubs
   for ext-ssh2.** Verified with a probe function in the user stub that
   PHPStan continued to report as "function not found". The custom stub
   exists for IDE resolution; don't plan around stub overrides. New
   ext-ssh2 typing needs `@phpstan-ignore-next-line` at the wrapper.
3. **`@`-suppression at the ext-ssh2 boundary is necessary, not lazy.**
   ext-ssh2 emits `E_WARNING` on every recoverable false-return (auth
   rejected, file missing, peer gone). PHPUnit + Behat convert warnings
   to exceptions, which would short-circuit the typed exceptions the
   wrapper exists to throw. `@` belongs ONLY inside `Ssh2Functions`; the
   layers above it must surface typed exceptions, not raw warnings.
4. **`atmoz/sftp` mounts volumes as root**, not as the configured user —
   `/etc/sftp.d/chown.sh` (one-line script chowning `/home/tester/data`
   to uid 1001) is required for any write-side test to pass. Lives at
   `tests/functional/fixtures/sftp.d/chown.sh`.

## Running things locally

```bash
composer install
composer qa                          # php-cs-fixer (dry) + phpstan + phpunit
composer cs-fix                      # apply CS fixes
composer stan                        # phpstan level max on src/
composer test                        # phpunit (100% line coverage gate)
tests/functional/bin/up              # start dockerised SFTP fixture
composer behat                       # 12 scenarios against the fixture
tests/functional/bin/down            # stop + remove fixture
```

CI runs the same on PHP 8.2 / 8.3 / 8.4 — see
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## Conventions

- **PHP 8.2+ only.** `declare(strict_types=1);` at the top of every file.
- **PHPStan level max on `src/` only.** Tests are validated by PHPUnit at
  runtime; running PHPStan over them adds noise (mock objects can't satisfy
  `resource` parameter types) without catching real bugs.
- **`@phpstan-ignore-*` is allowed only inside [`src/Ssh2/Ssh2Functions.php`](src/Ssh2/Ssh2Functions.php)** —
  the single documented boundary over the procedural ext-ssh2 API.
  Disallowed elsewhere in `src/`.
- **PHP `@`-operator suppression is a separate convention.** It is
  expected on the direct ext-ssh2 calls inside
  [`Ssh2Functions`](src/Ssh2/Ssh2Functions.php) (libssh2 emits
  `E_WARNING` on every recoverable false-return, which PHPUnit / Behat
  convert to exceptions and would short-circuit the typed exceptions
  the wrapper exists to throw). It is *also* allowed on stream-wrapper
  opens (`@fopen('ssh2.sftp://…')`) and stdlib file ops
  (`@hash_file`, `@file_put_contents`) elsewhere in `src/` — these
  stream wrappers raise `E_WARNING` on remote-side failures whose
  false-return is the typed signal we then convert into an
  `SshException`. New `@`-sites outside `Ssh2Functions` need an
  inline comment justifying which warning they suppress.
- **100% line coverage on `src/`** excluding `Ssh2Functions.php` (covered
  by Behat). The gate is enforced by
  [`tests/bin/check-coverage.php`](tests/bin/check-coverage.php) in CI.
- **PHP-CS-Fixer rules**: `@PER-CS2.0` + `@PHP82Migration` — see
  [`.php-cs-fixer.dist.php`](.php-cs-fixer.dist.php).
- **No commits unless asked.** Current working policy: build/edit on
  `master`, leave uncommitted so the user reviews the diff.
- **Don't extend the bundled PHPStan ext-ssh2 stubs.** They're correct
  for ext-ssh2 1.4.x (resource-based), and PHPStan 2.x's `stubFiles:`
  doesn't actually override them anyway. The custom stub at
  [`tests/stubs/ssh2.stub.php`](tests/stubs/ssh2.stub.php) exists for IDE
  resolution; expect any new ext-ssh2 typing to need an
  `@phpstan-ignore-next-line` at the wrapper boundary.

## Useful files at a glance

### Source layout (domain-grouped sub-namespaces)

```
src/
├── Auth/            AuthMode, Credentials, CredentialsInterface
├── HostKey/         FingerprintAlgorithm, FingerprintEncoding
├── Retry/           RetryPolicyInterface, ExponentialBackoffRetryPolicy, NoRetryPolicy
├── Path/            PathValidator
├── Progress/        ProgressListenerInterface
├── Ssh2/            Ssh2Functions, Ssh2FunctionsInterface
├── Exception/       single-root hierarchy (SshException + 6 leaves)
├── SftpClient.php
└── SftpClientInterface.php
```

| Path | What |
|------|------|
| [`src/SftpClientInterface.php`](src/SftpClientInterface.php) | Public contract for the client. Lives alongside the implementation — no separate contracts package (that was tried in an earlier P1 revision and reverted as overkill for a single-purpose library). |
| [`src/SftpClient.php`](src/SftpClient.php) | Main implementation. Owns auth dispatch (the match on `AuthMode`) — `Credentials` is pure data. Wraps connect/upload/download/scp* in a `RetryPolicyInterface`. |
| [`src/Auth/`](src/Auth/) | Authentication domain: the `AuthMode` enum, `CredentialsInterface` (implement to plug Vault / Secrets Manager), `Credentials` (default immutable value object via named factories). |
| [`src/HostKey/`](src/HostKey/) | Host-key fingerprint verification: `FingerprintAlgorithm` + `FingerprintEncoding` enums, integer-backed to mirror ext-ssh2's `SSH2_FINGERPRINT_*` bits. |
| [`src/Retry/`](src/Retry/) | Retry strategy: `RetryPolicyInterface` + two stock implementations (`ExponentialBackoffRetryPolicy`, `NoRetryPolicy`). |
| [`src/Path/`](src/Path/) | Path safety: `PathValidator` (also reused by consumers to validate untrusted input upstream). |
| [`src/Progress/`](src/Progress/) | `ProgressListenerInterface` (unwired pending P6). |
| [`src/Ssh2/`](src/Ssh2/) | ext-ssh2 boundary: `Ssh2FunctionsInterface` is the test seam; `Ssh2Functions` is the only file in the codebase that touches ext-ssh2 directly. |
| [`src/Exception/`](src/Exception/) | Single concrete hierarchy. Every library exception extends [`SshException`](src/Exception/SshException.php), so `catch (SshException $e)` catches anything this library throws. No marker interfaces — narrow with the concrete leaves (`AuthenticationException`, `ConfigurationException`, `ConnectionException`, `RemoteFilesystemException`, `TransferException`, `InvalidPathException`) when you need to react differently to different failures. Kept flat (not distributed under each domain) so the single-root hierarchy is visible at a glance. |
| [`tests/unit/SftpClientTest.php`](tests/unit/SftpClientTest.php) | Main test class (mocks adapter, uses `FakeSftpStreamWrapper`). |
| [`tests/functional/`](tests/functional/) | Behat suite + docker fixture. |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-version history (what 1.0 changed, what each 1.1 phase shipped, deltas vs. the original plan). |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy, supported-version matrix, hardening already in place. |
| [`COMPATIBILITY.md`](COMPATIBILITY.md) | SemVer policy (covered surface vs. internal, deprecation policy). |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Local dev setup, test layers, PR checklist. |
