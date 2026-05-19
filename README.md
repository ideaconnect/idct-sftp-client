# idct/sftp-client

Typed PHP 8.2+ wrapper around `ext-ssh2` that simplifies file upload / download
over SSH / SCP / SFTP. Built for predictable error handling, fingerprint
verification, and a clean unit-testable seam over the procedural `ssh2_*` API.

The 1.1 line adds atomic uploads, resume, recursive directory operations,
streaming sources/sinks, progress callbacks, retry policies, known-hosts
verification, and opt-in checksum verification — see the [feature index](#features)
below.

## Sponsorship ❤️

This project is maintained on the side and looking for sponsors to keep the
modernization moving forward. If your team relies on it, please consider
chipping in — every contribution helps keep this library alive:

[![Sponsor on GitHub](https://img.shields.io/github/sponsors/ideaconnect?style=for-the-badge&logo=githubsponsors&logoColor=white&label=Sponsor&color=ea4aaa)](https://github.com/sponsors/ideaconnect)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/idct)

Thank you to everyone who already supports the project! 🙏

## Contents

- [Sponsorship ❤️](#sponsorship-️)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Features](#features) — thematic feature index
- [Authentication](#authentication)
- [Host-key fingerprint verification](#host-key-fingerprint-verification)
- [Operations](#operations)
- [Atomic uploads & resume](#atomic-uploads--resume)
- [Streaming uploads / downloads (incl. S3 sources)](#streaming-uploads--downloads-incl-s3-sources)
- [Progress tracking](#progress-tracking)
- [Recursive directory operations](#recursive-directory-operations)
- [Retry policy](#retry-policy)
- [Checksum verification](#checksum-verification)
- [Prefixes](#prefixes)
- [Error handling](#error-handling)
- [Logging](#logging)
- [Examples](#examples) — runnable scripts under [`examples/`](examples/)
- [Upgrading from 0.x](#upgrading-from-0x)
- [Development](#development)
- [License](#license)

## Requirements

| Component   | Version           |
|-------------|-------------------|
| PHP         | `>= 8.2`          |
| ext-ssh2    | `>= 1.4`          |
| libssh2     | `>= 1.10`         |

Install ext-ssh2 (Debian/Ubuntu):

```bash
sudo apt-get install php-ssh2
```

Alpine:

```bash
apk add php-pecl-ssh2
```

Or manually using PECL

```bash
pecl install ssh2
```

(depending on your OS it may be required to install the `ssh2-beta` version)

## Installation

```bash
composer require idct/sftp-client:^1.1
```

## Quick start

```php
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\SftpClient;

$client = new SftpClient();
$client->setCredentials(Credentials::withPassword('alice', 'super-secret'));
$client->connect(
    host: 'sftp.example.com',
    port: 22,
    timeoutSeconds: 5,
    expectedFingerprint: 'a1b2c3...your sha1 hex...',
);

$client->upload('/local/path/file.bin', '/remote/incoming/file.bin');
$client->download('/remote/outgoing/report.csv', '/local/reports/report.csv');

$client->close();
```

`SftpClient` implements `__destruct()` that closes the SSH session, so leaked
instances still send `SSH_MSG_DISCONNECT` to the peer.

> **Verified by Behat:** [`readme.feature → Quick start round-trips a small file`](tests/functional/features/readme.feature)

## Features

| Topic | Where to read more |
|---|---|
| Authentication (password / pubkey / both / loader) | [§ Authentication](#authentication) |
| Host-key fingerprint pinning + `known_hosts` file | [§ Host-key fingerprint verification](#host-key-fingerprint-verification) |
| File ops (upload / download / SCP / stat / mkdir / rmdir / …) | [§ Operations](#operations) |
| **Atomic uploads + resume** | [§ Atomic uploads & resume](#atomic-uploads--resume) |
| **Streaming sources / sinks (e.g. S3)** | [§ Streaming uploads / downloads](#streaming-uploads--downloads-incl-s3-sources) |
| **Progress callbacks** | [§ Progress tracking](#progress-tracking) |
| **Recursive directory operations** | [§ Recursive directory operations](#recursive-directory-operations) |
| **Retry policy & lazy reconnect** | [§ Retry policy](#retry-policy) |
| Checksum verification (opt-in) | [§ Checksum verification](#checksum-verification) |
| Logging (PSR-3) | [§ Logging](#logging) |
| Runnable examples | [`examples/`](examples/) |
| SemVer policy | [`COMPATIBILITY.md`](COMPATIBILITY.md) |
| Disclosure policy | [`SECURITY.md`](SECURITY.md) |

## Authentication

```php
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Auth\StaticCredentialsLoader;

// password
Credentials::withPassword('alice', 'secret');

// public key
Credentials::withPublicKey('alice', '/path/id_rsa.pub', '/path/id_rsa', 'passphrase-or-null');

// multi-factor: both pubkey AND password legs must succeed
Credentials::withBoth('alice', 'secret', '/path/id_rsa.pub', '/path/id_rsa');

// anonymous (ssh2_auth_none)
Credentials::withNone('guest');
```

`Credentials` is a `final readonly` value object. Password and passphrase
parameters are marked `#[\SensitiveParameter]` so they are redacted from PHP
stack traces, and `__debugInfo()` replaces them with `***REDACTED***` in
`var_dump` / `print_r` / error-log dumps.

For dynamic per-host secret resolution (Vault, AWS Secrets Manager,
GCP Secret Manager, …), implement
`IDCT\Networking\Ssh\Auth\CredentialsLoaderInterface` and wire it in:

```php
$client->setCredentialsLoader($myVaultLoader);     // fires on every connect()
// Mutually exclusive with setCredentials().
```

For after-the-fact rate-limiting on auth failures:

```php
use IDCT\Networking\Ssh\Auth\AuthFailureRateLimiter;

$client->setAuthFailureRateLimiter(new AuthFailureRateLimiter(
    thresholdFailures: 3,
    baseDelayMs: 1_000,
    maxDelayMs: 60_000,
));
```

> **Verified by Behat:**
> [`connect.feature`](tests/functional/features/connect.feature) (password / wrong-password / pubkey),
> [`readme.feature → setCredentialsLoader resolves credentials at connect-time`](tests/functional/features/readme.feature).
> **Unit tests:** [`AuthFailureRateLimiterTest`](tests/unit/Auth/AuthFailureRateLimiterTest.php), [`CredentialsLoaderTest`](tests/unit/Auth/CredentialsLoaderTest.php).

## Host-key fingerprint verification

```php
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;

$client->connect(
    'sftp.example.com',
    22,
    timeoutSeconds: 5,
    expectedFingerprint: '5b:32:...:...',
    fingerprintAlgorithm: FingerprintAlgorithm::Sha256,   // default
    fingerprintEncoding:  FingerprintEncoding::Hex,       // default
);
```

A mismatch immediately disconnects and throws `ConnectionException` — the
auth handshake never starts.

For persistent host pinning across runs, use an OpenSSH-format
`known_hosts` file:

```php
use IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy;

$client->connect(
    'sftp.example.com',
    22,
    knownHostsFile: '/etc/idct/known_hosts',
    onUnknownHost: UnknownHostPolicy::Reject,           // or TrustOnFirstUse
);
```

`TrustOnFirstUse` appends a custom `sha1-fpr` entry on first connection.
On subsequent connects the entry is matched. A key change at the same
host raises `ConnectionException` regardless of policy — mismatch is
always treated as a MITM signal.

> **Why SHA-1, not SHA-256:** `SSH2_FINGERPRINT_SHA256` only ships in
> libssh2 ≥ 1.9; the library's floor is `ext-ssh2 >= 1.4`. The
> `sha1-fpr` keytype is non-standard but OpenSSH skips unknown keytypes
> when reading the file, so the file remains safe to share with
> `ssh(1)`'s own entries. Details in
> [`src/KnownHosts/KnownHostsFile.php`](src/KnownHosts/KnownHostsFile.php).

> **Verified by Behat:** [`known-hosts.feature`](tests/functional/features/known-hosts.feature)
> (TOFU first connect + repeat connect, Reject on unknown host, tampered mismatch).
> Fingerprint mismatch via `expectedFingerprint`: [`connect.feature`](tests/functional/features/connect.feature).

## Operations

```php
$client->upload($local, $remote);                // SFTP, atomic by default
$client->download($remote, $local);              // SFTP
$client->scpUpload($local, $remote);             // SCP (never atomic — one-shot push)
$client->scpDownload($remote, $local);           // SCP

$client->remove('/data/file.bin');
$client->rename('/data/old.bin', '/data/new.bin');

$client->makeDirectory('/data/sub', mode: 0755, recursive: true);
$client->removeDirectory('/data/sub');           // must be empty

$client->stat('/data/file.bin');                 // stat-style array
$client->fileExists('/data/file.bin');           // bool
$client->getFileList('/data');                   // list<string>, no . / ..
$client->getFileList('/data', includeDotEntries: true);

$client->enableFileSizeVerification();           // post-transfer size check
```

> **Verified by Behat:**
> [`transfer.feature`](tests/functional/features/transfer.feature),
> [`filesystem.feature`](tests/functional/features/filesystem.feature),
> [`readme.feature → enableFileSizeVerification accepts a clean upload`](tests/functional/features/readme.feature).

## Atomic uploads & resume

`upload()` is atomic by default: the bytes land in a hidden
`.{basename}.partial-{uuid}` sibling, then `ssh2_sftp_rename`s onto the
final path. Mid-transfer failures are best-effort cleaned up; nothing
half-written ever appears at the destination filename. Disable on
servers that reject overwrite-on-rename:

```php
$client->disableAtomicUploads();
```

For resumable transfers on flaky links:

```php
// Auto-detect offset from any existing partial.
$client->resumeUpload('/local/giant.iso', '/remote/giant.iso');

// Or pass an explicit byte offset.
$client->resumeUpload('/local/giant.iso', '/remote/giant.iso', offset: 1_500_000);

// Downloads mirror it.
$client->resumeDownload('/remote/giant.iso', '/local/giant.iso');
```

Behaviour:

- `resumeUpload` appends to a deterministic `.{basename}.resume`
  sibling (libssh2's stream-wrapper accepts `'ab'` for open but
  `fwrite` returns false; we use `'r+b'` + seek to dodge that quirk).
  On success the partial is renamed onto the final path. **On failure
  the partial is preserved** so the next call can pick up where this
  one left off — opposite of atomic upload, which unlinks the partial.
- `resumeDownload` appends to the local file; if the local already
  equals the remote size, it's a clean no-op.

> **Verified by Behat:**
> [`atomic-and-resume.feature`](tests/functional/features/atomic-and-resume.feature)
> (atomic round-trip, resume from server-side partial, resume download into a partial local, noop when already complete),
> [`readme.feature → disableAtomicUploads writes the destination directly`](tests/functional/features/readme.feature).
> **Unit tests:** [`AtomicUploadAndResumeTest`](tests/unit/AtomicUploadAndResumeTest.php).
> **Runnable:** [`examples/03-resume-upload.php`](examples/03-resume-upload.php).

## Streaming uploads / downloads (incl. S3 sources)

The plain `upload()` / `download()` take filesystem paths. For sources
or sinks that aren't files — S3 objects, generated payloads, HTTP
bodies, in-memory buffers — use the stream variants:

```php
// Upload from any PHP stream resource.
$stream = fopen('http://my-minio:9000/bucket/key', 'rb');
$client->uploadStream($stream, '/remote/from-s3.bin');
fclose($stream);

// Download into any stream resource (returns bytes written).
$sink  = fopen('php://temp/maxmemory:0', 'r+b');
$bytes = $client->downloadStream('/remote/source.bin', $sink);
rewind($sink);
// … now hand $sink to whatever consumer wants the bytes.
```

`uploadStream` honours the atomic flag (writes to a partial, renames on
success). Both methods accept an optional `ProgressListenerInterface`
([§ Progress tracking](#progress-tracking)) and respect the configured
chunk size (`setChunkSize(int $bytes)`).

The plan's S3-from-AWS-SDK shape is the same as the HTTP `fopen` above
once you've called `\Aws\S3\S3Client::getObject(...)->get('Body')->detach()`
to get the underlying stream resource — no library-side AWS dependency
needed.

> **Verified by Behat:**
> [`s3-stream.feature`](tests/functional/features/s3-stream.feature)
> (round-trips a payload served by minio),
> [`streaming-progress.feature`](tests/functional/features/streaming-progress.feature)
> (uploadStream from `php://memory`, downloadStream into an in-memory sink).
> **Unit tests:** [`StreamingAndProgressTest`](tests/unit/StreamingAndProgressTest.php).
> **Runnable:** [`examples/07-stream-from-s3.php`](examples/07-stream-from-s3.php).

## Progress tracking

Implement `IDCT\Networking\Ssh\Progress\ProgressListenerInterface` and
pass it to any transfer:

```php
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;

final class CliProgressBar implements ProgressListenerInterface
{
    public function started(string $operation, ?int $totalBytes): void
    {
        echo "[$operation] starting ($totalBytes bytes)\n";
    }
    public function progress(int $bytesDone): void
    {
        echo "\r  $bytesDone bytes …";
    }
    public function completed(int $bytesDone): void
    {
        echo "\r  done. $bytesDone bytes.\n";
    }
    public function failed(\Throwable $e): void
    {
        echo "\n  FAILED: " . $e->getMessage() . "\n";
    }
}

$client->upload('/local/big.iso', '/remote/big.iso', progress: new CliProgressBar());
```

Lifecycle contract: `started → progress × N → exactly one of completed | failed`.
The terminator covers the whole operation, so atomic-rename failures fire
`failed()` not a stray `completed()`. SCP transfers do NOT emit events —
ext-ssh2 doesn't expose libssh2's per-chunk callbacks for `scp_send` / `scp_recv`.

Granularity is bounded by `chunkSize` (default 1 MiB). For finer-grained
bars, tune it:

```php
$client->setChunkSize(64 * 1024);   // 64 KiB chunks → ~16 progress events per MiB
```

> **Verified by Behat:**
> [`streaming-progress.feature`](tests/functional/features/streaming-progress.feature)
> (lifecycle started → progress → completed for "upload", final byte count).
> **Unit tests:** [`StreamingAndProgressTest`](tests/unit/StreamingAndProgressTest.php).
> **Runnable:** [`examples/02-progress.php`](examples/02-progress.php).

## Recursive directory operations

```php
use IDCT\Networking\Ssh\Directory\ConflictPolicy;
use IDCT\Networking\Ssh\Directory\SymlinkPolicy;

// Upload a local tree, mirroring its layout under /backup/.
$result = $client->uploadDirectory(
    '/local/src',
    '/backup/src',
    onConflict: ConflictPolicy::Skip,        // or Overwrite (default) / Fail
    symlinks:   SymlinkPolicy::Skip,         // or Follow (with cycle detection)
    bestEffort: true,                        // collect failures instead of aborting
);
echo "Uploaded {$result->filesTransferred} files, "
   . "{$result->bytesTransferred} bytes, "
   . count($result->skipped) . " skipped, "
   . count($result->failures) . " failures.\n";

// Mirror it back.
$client->downloadDirectory('/backup/src', '/local/restore');

// Walk arbitrary trees (post-order generator: children before parents).
foreach ($client->walk('/backup') as $entry) {
    echo $entry->path . " ({$entry->type->name})\n";
}

// rm -rf on the remote.
$client->removeDirectoryTree('/backup/obsolete');
```

The result types are immutable `UploadResult` / `DownloadResult` value
objects with `filesTransferred`, `bytesTransferred`, `skipped`, and
`failures` (a `list<DirectoryFailure>` populated only in best-effort
mode). Per-file transfers reuse the existing `upload()` / `download()`
so atomic writes, retries, file-size verification, and progress all
apply on a per-file basis.

`SymlinkPolicy::Follow` is supported on the upload side with inode-set
cycle detection (`(dev, ino)` tracking). On the download side, remote
symlink-follow is documented as a deferred feature — the entry is
recorded in `skipped` with a notice log line.

> **Verified by Behat:**
> [`directory-ops.feature`](tests/functional/features/directory-ops.feature)
> (nested round-trip + tree removal),
> [`readme.feature → walk() yields nested entries in post-order`](tests/functional/features/readme.feature).
> **Unit tests:** [`DirectoryOperationsTest`](tests/unit/DirectoryOperationsTest.php),
> [`Directory/DirectoryPolicyTest`](tests/unit/Directory/DirectoryPolicyTest.php) (ConflictPolicy / SymlinkPolicy / best-effort).
> **Runnable:** [`examples/05-upload-directory.php`](examples/05-upload-directory.php),
> [`examples/06-walk-and-cleanup.php`](examples/06-walk-and-cleanup.php).

## Retry policy

Every transfer is wrapped in a `RetryPolicyInterface`. The default is
`ExponentialBackoffRetryPolicy` (5 retries, 200 ms base, 30 s cap, ±30%
jitter). Swap or disable per-client:

```php
use IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;

$client = new SftpClient(
    enableFileSizeVerification: false,
    ssh2: null,
    retryPolicy: new ExponentialBackoffRetryPolicy(maxRetries: 10, baseMs: 100),
);

// Or swap at runtime.
$client->setRetryPolicy(new NoRetryPolicy());
```

The retry helper:

1. **Never retries** `AuthenticationException`, `ConfigurationException`,
   or `InvalidPathException` — those are caller bugs, not transient.
2. **Always retries** `ConnectionException` (transport-level).
3. Retries `TransferException` only on a curated message-fragment
   allowlist (`Failed to copy`, `Unable to open remote`,
   `Could not SCP-download`, `Could not SCP-upload`) — anything else
   indicates real filesystem state and is propagated.
4. On each retry, if the SSH session is detected dead via `ping()`, it
   runs a one-shot `doConnect()` to revive it. The stored connect args
   are reused so transparent re-establishment is automatic.

`SftpClient::ping(): bool` is also exposed as a cheap keepalive (it
stats `/` over SFTP and never throws).

To write your own policy:

```php
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;

final class MyPolicy implements RetryPolicyInterface
{
    public function nextDelayMs(int $attempt, SshException $lastError): int
    {
        return $attempt > 3 ? 0 : 500;        // 500 ms each, 3 attempts max
    }
}
```

> **Verified by Behat:**
> [`fault-injection.feature`](tests/functional/features/fault-injection.feature)
> (latency + bandwidth-cap toxics: retry holds up under real adversity),
> [`readme.feature → setRetryPolicy(NoRetryPolicy) at runtime takes effect`](tests/functional/features/readme.feature),
> [`readme.feature → ping() returns true / false`](tests/functional/features/readme.feature).
> **Unit tests:** [`RetryWiringTest`](tests/unit/RetryWiringTest.php),
> [`ExponentialBackoffRetryPolicyTest`](tests/unit/ExponentialBackoffRetryPolicyTest.php),
> [`NoRetryPolicyTest`](tests/unit/NoRetryPolicyTest.php).
> **Runnable:** [`examples/04-retry-policy.php`](examples/04-retry-policy.php).

## Checksum verification

For end-to-end integrity beyond size verification, plug a
`RemoteHasherInterface` implementation:

```php
use IDCT\Networking\Ssh\Checksum\ShellSumRemoteHasher;
use IDCT\Networking\Ssh\Checksum\RedownloadRemoteHasher;

// Option 1: run `sha256sum` on the server (needs shell access).
$client->setRemoteHasher(new ShellSumRemoteHasher('sha256', 'sha256sum'));

// Option 2: re-download the file and hash it locally
// (no server dependency, but doubles transfer time).
$client->setRemoteHasher(new RedownloadRemoteHasher('sha256'));

// All subsequent upload / resumeUpload / download / resumeDownload
// transfers now compare local + remote digests after the transfer and
// throw TransferException on mismatch.
$client->upload('/local/critical.bin', '/remote/critical.bin');
```

> **Verified by Behat:** [`readme.feature → RedownloadRemoteHasher passes on a clean round-trip`](tests/functional/features/readme.feature).
> **Unit tests:** [`Checksum/RemoteHasherTest`](tests/unit/Checksum/RemoteHasherTest.php).

## Prefixes

```php
$client->setLocalPrefix('/var/local/inbox/');
$client->setRemotePrefix('/uploads/');

$client->upload('/var/sources/report.csv');                   // → /uploads/report.csv (basename)
$client->upload('/var/sources/report.csv', 'q3/report.csv');  // → /uploads/q3/report.csv
$client->upload('/var/sources/report.csv', '/abs/dest.csv');  // → /abs/dest.csv (absolute bypasses prefix)
```

`setRemotePrefix` is applied to BOTH sides of `rename()` (the original 0.x
applied it only to the source — that was bug B6, fixed in 1.0).

> **Verified by Behat:** [`readme.feature → setRemotePrefix applies to relative paths`](tests/functional/features/readme.feature),
> [`readme.feature → an absolute remote path bypasses the remote prefix (T6 contract)`](tests/functional/features/readme.feature).

## Error handling

All errors are typed exceptions extending `IDCT\Networking\Ssh\Exception\SshException`
(itself a `RuntimeException`):

| Exception                    | When                                          |
|------------------------------|-----------------------------------------------|
| `ConfigurationException`     | Missing credentials, bad mode, invalid key path |
| `ConnectionException`        | TCP/handshake failure, fingerprint mismatch, no SFTP session yet |
| `AuthenticationException`    | `ssh2_auth_*` rejected the credentials        |
| `TransferException`          | Upload / download / SCP failure               |
| `RemoteFilesystemException`  | Remote stat / mkdir / rmdir / rename / unlink / list failure |
| `InvalidPathException`       | Path validation rejected the input (extends `ConfigurationException`) |

```php
use IDCT\Networking\Ssh\Exception;

try {
    $client->download('/data/big.bin', '/local/big.bin');
} catch (Exception\ConnectionException) {
    // reconnect
} catch (Exception\TransferException $e) {
    // log, alert, retry
} catch (Exception\SshException $e) {
    // anything else from this library — single SshException root grabs all of them
}
```

> **Verified by Behat:** [`readme.feature → Every library error is caught by the SshException root`](tests/functional/features/readme.feature).
> **Unit tests:** [`Exception/ExceptionHierarchyTest`](tests/unit/Exception/ExceptionHierarchyTest.php).

## Logging

```php
$client->setLogger(new Monolog\Logger('sftp'));
$client->setLogContext(['request_id' => 'abc-123', 'tenant' => 'acme']);
```

`SftpClient` implements `Psr\Log\LoggerAwareInterface` (defaults to `NullLogger`).
Every record carries a `correlation_id` (per-connection 16-char hex), `host`,
and `port` for downstream log aggregation. A lint test
([`tests/unit/LoggerRedactionLintTest.php`](tests/unit/LoggerRedactionLintTest.php))
fails the build if any source line contains `password` / `passphrase` near a
log call.

> **Verified by Behat:** [`readme.feature → setLogContext merges static fields into every record`](tests/functional/features/readme.feature)
> (asserts every captured record carries the caller-supplied `tenant` + `request_id` keys plus the auto-injected `correlation_id`).
> **Unit tests:** [`LoggerIntegrationTest`](tests/unit/LoggerIntegrationTest.php).

## Examples

Runnable scripts live in [`examples/`](examples/). They connect to the
dockerised SFTP fixture used by the Behat suite — see
[`examples/README.md`](examples/README.md) for the one-line bring-up
command.

> **Verified by Behat:** Every README code sample also has a matching
> scenario in [`tests/functional/features/readme.feature`](tests/functional/features/readme.feature)
> (13 scenarios at last count). The "Verified by Behat" callouts under
> each section above point at the specific scenario backing the example.

| # | Script | What it shows |
|---|---|---|
| 01 | [`01-basic.php`](examples/01-basic.php) | Round-trip a file via SFTP |
| 02 | [`02-progress.php`](examples/02-progress.php) | CLI progress bar via `ProgressListenerInterface` |
| 03 | [`03-resume-upload.php`](examples/03-resume-upload.php) | Abort an upload mid-stream and resume |
| 04 | [`04-retry-policy.php`](examples/04-retry-policy.php) | Customise `ExponentialBackoffRetryPolicy` |
| 05 | [`05-upload-directory.php`](examples/05-upload-directory.php) | Recursive upload with `ConflictPolicy::Skip` |
| 06 | [`06-walk-and-cleanup.php`](examples/06-walk-and-cleanup.php) | `walk()` + `removeDirectoryTree()` |
| 07 | [`07-stream-from-s3.php`](examples/07-stream-from-s3.php) | `uploadStream` an HTTP object served by minio |

## Upgrading from 0.x

| 0.x                                           | 1.x                                          |
|-----------------------------------------------|----------------------------------------------|
| `new AuthMode::PASSWORD` (class const)        | `AuthMode::Password` (`enum` under `Auth\`)  |
| `new Credentials(); ->setMode(); ->setUsername(); …` | `Credentials::withPassword($u, $p)` etc.  |
| `\Exception` everywhere                       | typed `Exception\*` hierarchy under one `SshException` root |
| `$client->connect($host, $port)`              | same, plus `timeoutSeconds`, `expectedFingerprint`, `fingerprintAlgorithm`, `fingerprintEncoding`, `knownHostsFile`, `onUnknownHost`, `securityProfile` |
| `Credentials::withPublicKey(...)` accepted any string | now validates that the key files exist |
| `rename($from, $to)` applied prefix only to `$from` | applies prefix to both sides            |
| `getFileList()` returned `.` and `..`         | filtered by default; `includeDotEntries: true` to keep |
| `close()` ran `ssh2_exec($conn, 'logout')` (broken) | uses `ssh2_disconnect()`               |
| Upload landed bytes directly at the destination | atomic `.partial-{uuid}` + rename by default |

Class moves (1.1): everything under `IDCT\Networking\Ssh\…` is now grouped
by domain (`Auth\`, `HostKey\`, `Retry\`, `Path\`, `Progress\`, `Ssh2\`,
`Directory\`, `KnownHosts\`, `Checksum\`, `Security\`). The
[`CHANGELOG.md`](CHANGELOG.md) "P1 (revised)" section has the full
old→new FQN table.

See [`CHANGELOG.md`](CHANGELOG.md) for the per-version history — 1.0
covers the bug-fix list (`B1`–`B12`) and security baseline (`S1`–`S5`)
from the original modernization pass; 1.1 covers the production-grade
feature work (`P1`–`P11`).

## Development

```bash
composer install
composer qa                   # cs check + phpstan + phpunit
composer cs-fix               # apply CS fixes
composer stan                 # phpstan level max
composer test                 # phpunit (100% line coverage gate)
composer infection            # mutation testing (gates at 85 MSI / 85 covered MSI)
tests/functional/bin/up       # start dockerised SFTP fixtures (atmoz + openssh + minio + toxiproxy)
composer behat                # run Behat against the fixture
SFTP_PORT=2223 composer behat # run the same suite against OpenSSH 9.x
tests/functional/bin/down     # stop fixture
```

CI runs PHP 8.2 / 8.3 / 8.4 across both atmoz and OpenSSH 9.x backends in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). The unit-test
coverage gate enforces **100% line coverage** on every file except
`src/Ssh2/Ssh2Functions.php` (the thin ext-ssh2 delegation layer covered
by Behat).

## License

MIT — see `LICENSE`.
