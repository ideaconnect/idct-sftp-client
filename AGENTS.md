# AGENTS.md

Onboarding notes for AI agents (and humans) picking up work on this repo.

## Where the work lives

**Active backlog: Asana, under `MYID-4` ("Release idct-sftp-client v1.0")**
GID `1214894683655126` — [open in Asana](https://app.asana.com/1/1214897106264347/project/1214894683655121/task/1214894683655126).

The 12 subtasks of MYID-4 are the production-grade plan (one subtask per
phase, in execution order). Each subtask's description summarises scope
and acceptance criteria; the full rationale lives in
[PRODUCTION_GRADE.md](PRODUCTION_GRADE.md).

If you have the Asana MCP wired up, prefer fetching the subtask list via
`search_tasks` / `get_task task_id=1214894683655126` over reading
PRODUCTION_GRADE.md — the doc is the *plan*, the tasks are the *status*.

| Phase | What | Plan §        |
|------:|------|---------------|
| P1    | Public contract surface (interfaces + single SshException root) | §P1 |
| P2    | Path safety & input validation                   | §P2 |
| P7    | PSR-3 logger integration                         | §P7 |
| P5    | Retry policy & connection lifecycle              | §P5 |
| P4    | Atomic transfers & resume                        | §P4 |
| P6    | Streaming & progress callbacks                   | §P6 |
| P3    | Recursive directory operations                   | §P3 |
| P8    | Security hardening (round 2)                     | §P8 |
| P9    | Alternative backend evaluation (deferred)        | §P9 |
| P11   | Test additions (multi-server, soak, mutation)    | §P11 |
| P10   | Operational maturity (release automation, etc.)  | §P10 |
| P12   | Documentation                                    | §P12 |

P13 in the doc is the **explicit out-of-scope list** — no Asana task,
deliberate non-goals (async, framework adapters, OpenTelemetry, connection
pooling). Read it before proposing one of those.

## How the repo got here

[MODERNIZE.md](MODERNIZE.md) is the historical plan that took the library
from 0.x to 1.0 — bug fix table (B1–B12), security items (S1–S5), and a
final §10 "What the plan got wrong" recording the four reality checks
that bit during implementation (ext-ssh2 1.4 still returns resources, not
objects; PHPStan stubFiles don't override bundled JetBrains stubs;
`@`-suppression at the ext-ssh2 boundary is necessary, not lazy;
atmoz/sftp mounts volumes as root). Read §10 before changing
`src/Ssh2Functions.php` or `tests/stubs/ssh2.stub.php`.

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
- **`@phpstan-ignore-*` is allowed only inside [`src/Ssh2Functions.php`](src/Ssh2Functions.php)** —
  the single documented boundary over the procedural ext-ssh2 API.
  Disallowed elsewhere in `src/`.
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
| [`PRODUCTION_GRADE.md`](PRODUCTION_GRADE.md) | What to build next. |
| [`MODERNIZE.md`](MODERNIZE.md) | How we got here. |
| [`CHANGELOG.md`](CHANGELOG.md) | What 1.0 changed. |
