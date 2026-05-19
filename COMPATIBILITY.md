# Compatibility Promise

This document defines what the SemVer version number actually covers
for `idct/sftp-client`. A patch / minor upgrade that breaks anything
listed in **Covered surface** is a bug; a change to anything listed in
**Internal** is allowed at any version bump.

## Versioning

Releases follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X.0.0) — a backwards-incompatible change to the covered
  surface. Consumers may need to edit code to upgrade.
- **MINOR** (x.Y.0) — added behaviour that doesn't break existing
  consumers. New methods, new optional parameters with defaults, new
  enum cases on enums the consumer doesn't `match` exhaustively.
- **PATCH** (x.y.Z) — bug fixes and internal-only changes.

Patch upgrades are always safe within a major version. Minor upgrades
should be safe unless you've subclassed library code or written
exhaustive `match` over our enums.

## Covered surface

These are the things SemVer protects. Breaking changes here are MAJOR.

### Interfaces

- `IDCT\Networking\Ssh\SftpClientInterface`
- `IDCT\Networking\Ssh\Auth\CredentialsInterface`
- `IDCT\Networking\Ssh\Retry\RetryPolicyInterface`
- `IDCT\Networking\Ssh\Progress\ProgressListenerInterface`

For each: the method names, parameter names (for named-arg callers),
parameter types, parameter order, return types. Adding a new method to
an interface IS a breaking change for consumers that implement it; we
will only do that at a major bump.

### Public concrete classes

- `IDCT\Networking\Ssh\SftpClient` — every public method's signature
  and observable behaviour.
- `IDCT\Networking\Ssh\Auth\Credentials` — named factories
  (`withPassword`, `withPublicKey`, etc.) and public readonly
  properties.
- `IDCT\Networking\Ssh\Path\PathValidator` — `validateRemotePath()` /
  `joinRemote()` signatures and rejection rules. The rejection rules
  are part of the contract: relaxing them is a breaking change in the
  security direction.
- `IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy` and
  `NoRetryPolicy` — public constructors and behaviour.
- `IDCT\Networking\Ssh\KnownHosts\KnownHostsFile` — `verifyHost()` /
  `appendFingerprint()` signatures and the file-format contract.

### Enums

- `IDCT\Networking\Ssh\Auth\AuthMode`
- `IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm`
- `IDCT\Networking\Ssh\HostKey\FingerprintEncoding`
- `IDCT\Networking\Ssh\Directory\EntryType`
- `IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy`
- `IDCT\Networking\Ssh\KnownHosts\HostKeyDecision`

For each enum: the set of cases. **Adding** a case is a minor bump
because consumers who exhaustively `match` will need a new arm — but
PHP enums don't enforce exhaustiveness so this is closer to the
"minor" side of the line. **Removing** a case or **renaming** one is
major.

### Concrete exception classes

The exception class names, their inheritance lineage (`SshException` as
the single root, `InvalidPathException extends ConfigurationException`,
etc.), and the FQNs are all covered. Renaming or moving an exception
is a major bump.

What is **not** covered: the exact `getMessage()` text. We may tweak
wording in any release. Catch by class; don't substring-match the
message.

### Value-object DTOs

- `IDCT\Networking\Ssh\Directory\RemoteEntry`
- `IDCT\Networking\Ssh\Directory\UploadResult`
- `IDCT\Networking\Ssh\Directory\DownloadResult`

Public readonly properties and constructor parameter names + types are
covered. Adding a new property with a default is a minor bump; adding
one without a default is a major bump (it breaks positional
construction).

## Internal

These are NOT covered by SemVer. We may change them in any release
without a major bump:

- Anything in `src/` declared `private` or `protected`.
- The exact text of any `getMessage()` or log record message.
- The internal namespace structure inside `src/Ssh2/` — this is the
  ext-ssh2 boundary; if libssh2 changes we will reshape this freely.
- `src/Ssh2/Ssh2FunctionsInterface` and its default implementation —
  it's a test seam, not part of the consumer-facing API. Custom
  implementations are not promised to keep working across versions.
- Coverage / mutation / lint configuration (`phpunit.xml.dist`,
  `phpstan.neon.dist`, `infection.json5`, `.php-cs-fixer.dist.php`).
- The Behat suite's step definitions and feature files.
- The dockerised SFTP fixture (`tests/functional/docker-compose.yml`,
  `bin/up`, `bin/down`).
- Internal helper methods on `SftpClient` (`doConnect`, `doUpload`,
  `retry`, `cleanupPartial`, etc.) even though they're not strictly
  `private`-prefixed by visibility.

## Deprecation policy

When we decide to remove or change a covered-surface item:

1. The replacement ships in a MINOR release with the old item marked
   `@deprecated` in its docblock. The CHANGELOG entry says what to use
   instead.
2. The deprecated item keeps working for **at least one full minor
   release cycle** before removal.
3. Removal happens in the next MAJOR.

We will not deprecate-and-remove anything inside a single MAJOR.

## ext-ssh2 / libssh2 floor

The library declares `ext-ssh2 >= 1.4`. Bumping that floor (e.g. to
require an `ext-ssh2` version that ships `SSH2_FINGERPRINT_SHA256`) is
a MAJOR change. We will not raise it mid-major even to unlock new
features — those features will be opt-in and gracefully degrade on the
old floor instead, OR they will ship in the next major.

## PHP version floor

Same rule as `ext-ssh2`: the `php` constraint in `composer.json` is
covered surface. Raising it (e.g. PHP 8.2 → 8.4) is a MAJOR change.

## Out-of-scope surface

These appear in the codebase but are NOT promised:

- Anything under `tests/` (unit / functional / support classes).
- Anything under `docs/` that isn't explicitly tagged "covered".
- The CLI tooling implied by composer scripts (`composer infection`,
  `composer cs-fix` flags).
- The exact content of log records — both the `message` field and the
  `context` array keys may grow or change. The presence of the
  documented base context (`correlation_id`, `host`, `port`) is the
  only promise.
