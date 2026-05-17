# idct/sftp-client

Typed PHP 8.2+ wrapper around `ext-ssh2` that simplifies file upload/download
over SSH/SCP/SFTP. Built for predictable error handling, fingerprint
verification, and a clean unit-testable seam over the procedural ssh2 API.

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

macOS (Homebrew):

```bash
pecl install ssh2-alpha
```

## Installation

```bash
composer require idct/sftp-client:^1.0
```

## Quick start

```php
use IDCT\Networking\Ssh\Credentials;
use IDCT\Networking\Ssh\SftpClient;

$client = new SftpClient();
$client->setCredentials(Credentials::withPassword('alice', 'super-secret'));
$client->connect(
    host: 'sftp.example.com',
    port: 22,
    timeoutSeconds: 5,
    expectedFingerprint: 'a1b2c3...your sha256 hex...',
);

$client->upload('/local/path/file.bin', '/remote/incoming/file.bin');
$client->download('/remote/outgoing/report.csv', '/local/reports/report.csv');

$client->close();
```

`SftpClient` implements `__destruct()` that closes the SSH session, so leaked
instances still send `SSH_MSG_DISCONNECT` to the peer.

## Authentication

```php
// password
Credentials::withPassword('alice', 'secret');

// public key
Credentials::withPublicKey('alice', '/path/id_rsa.pub', '/path/id_rsa', 'passphrase-or-null');

// multi-factor: both pubkey and password legs must succeed
Credentials::withBoth('alice', 'secret', '/path/id_rsa.pub', '/path/id_rsa');

// anonymous (ssh2_auth_none)
Credentials::withNone('guest');
```

`Credentials` is a `final readonly` value object. Password and passphrase
parameters are marked `#[\SensitiveParameter]` so they are redacted from PHP
stack traces, and `__debugInfo()` replaces them with `***REDACTED***` in
`var_dump`/`print_r`/error-log dumps.

## Host-key fingerprint verification

```php
use IDCT\Networking\Ssh\FingerprintAlgorithm;
use IDCT\Networking\Ssh\FingerprintEncoding;

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

## Operations

```php
$client->upload($local, $remote);                // SFTP
$client->download($remote, $local);              // SFTP
$client->scpUpload($local, $remote);             // SCP
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

## Prefixes

```php
$client->setLocalPrefix('/var/local/inbox/');
$client->setRemotePrefix('/uploads/');

$client->upload('/var/sources/report.csv');      // → /uploads/report.csv (basename)
$client->upload('/var/sources/report.csv', 'q3/report.csv'); // → /uploads/q3/report.csv
```

`setRemotePrefix` is applied to BOTH sides of `rename()` (the original 0.x
applied it only to the source — that was bug B6, fixed in 1.0).

## Error handling

All errors are typed exceptions extending `IDCT\Networking\Ssh\Exception\SshException`
(itself a `RuntimeException`):

| Exception                    | When                                          |
|------------------------------|-----------------------------------------------|
| `ConfigurationException`     | Missing credentials, bad mode, invalid key path |
| `ConnectionException`        | TCP/handshake failure, fingerprint mismatch, no SFTP session yet |
| `AuthenticationException`    | `ssh2_auth_*` rejected the credentials        |
| `TransferException`          | Upload/download/SCP failure                   |
| `RemoteFilesystemException`  | Remote stat/mkdir/rmdir/rename/unlink/list failure |

```php
use IDCT\Networking\Ssh\Exception;

try {
    $client->download('/data/big.bin', '/local/big.bin');
} catch (Exception\ConnectionException) {
    // reconnect
} catch (Exception\TransferException $e) {
    // log, alert, retry
} catch (Exception\SshException $e) {
    // anything else from this library
}
```

## Logging

```php
$client->setLogger(new Monolog\Logger('sftp'));
```

`SftpClient` implements `Psr\Log\LoggerAwareInterface` (defaults to `NullLogger`).

## Upgrading from 0.x

| 0.x                                           | 1.0                                          |
|-----------------------------------------------|----------------------------------------------|
| `new AuthMode::PASSWORD` (class const)        | `AuthMode::Password` (`enum`)                |
| `new Credentials(); ->setMode(); ->setUsername(); …` | `Credentials::withPassword($u, $p)` etc.  |
| `\Exception` everywhere                       | typed `Exception\*` hierarchy                |
| `$client->connect($host, $port)`              | same, plus `timeoutSeconds`, `expectedFingerprint`, `fingerprintAlgorithm`, `fingerprintEncoding` |
| `Credentials::withPublicKey(...)` accepted any string | now validates that the key files exist |
| `rename($from, $to)` applied prefix only to `$from` | applies prefix to both sides            |
| `getFileList()` returned `.` and `..`         | filtered by default; `includeDotEntries: true` to keep |
| `close()` ran `ssh2_exec($conn, 'logout')` (broken) | uses `ssh2_disconnect()`               |

See `MODERNIZE.md` for the full list of bug fixes (B1–B12) and security
hardening (S1–S5) shipped in 1.0.

## Development

```bash
composer install
composer qa                   # cs check + phpstan + phpunit
composer cs-fix               # apply CS fixes
composer stan                 # phpstan level max
composer test                 # phpunit
tests/functional/bin/up       # start dockerised SFTP fixture
composer behat                # run Behat against the fixture
tests/functional/bin/down     # stop fixture
```

CI runs PHP 8.2 / 8.3 / 8.4 in `.github/workflows/ci.yml`. The unit-test
coverage gate enforces **100% line coverage** on every file except
`src/Ssh2Functions.php` (the thin ext-ssh2 delegation layer covered by Behat).

## License

MIT — see `LICENSE`.
