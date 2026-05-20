# Runnable examples

Seven small scripts that exercise the 1.1 feature surface against the
dockerised SFTP fixture used by the Behat suite. Each script is
self-contained, prints what it's doing, and cleans up after itself.

## Prerequisites

- PHP 8.2+ with `ext-ssh2`
- `composer install` run from the repo root (these scripts use the same
  `vendor/autoload.php`)
- Docker + Docker Compose

## Bring up the fixture

```bash
# atmoz/sftp (port 2222) + OpenSSH 9.x (2223) + minio (9000) + toxiproxy (8474)
tests/functional/bin/up
```

The defaults below all assume **atmoz/sftp on `127.0.0.1:2222`** (user
`tester` / password `testerpass`) and **minio on `127.0.0.1:9000`** for
example 07. Override per-script via the `SFTP_HOST` / `SFTP_PORT` /
`SFTP_USER` / `SFTP_PASS` env vars if you point them at your own server.

When done:

```bash
tests/functional/bin/down
```

## The scripts

| # | Script | Demonstrates |
|---|---|---|
| 01 | [`01-basic.php`](01-basic.php) | Connect → upload → download → close. The "hello world" of SftpClient. |
| 02 | [`02-progress.php`](02-progress.php) | A simple CLI progress bar wired via `ProgressListenerInterface`. Sends 256 KiB through 16 KiB chunks so you actually see the bar move. |
| 03 | [`03-resume-upload.php`](03-resume-upload.php) | Half-upload a file (truncating its `.resume` partial), then call `resumeUpload()` to finish — verifies the bytes round-trip identically. |
| 04 | [`04-retry-policy.php`](04-retry-policy.php) | Plug a custom `RetryPolicyInterface` that prints every retry decision, then trigger a transient failure to see the backoff kick in. |
| 05 | [`05-upload-directory.php`](05-upload-directory.php) | Build a nested local tree, recursively upload it under `/data/example-tree/`, then re-run with `ConflictPolicy::Skip` to show idempotence. |
| 06 | [`06-walk-and-cleanup.php`](06-walk-and-cleanup.php) | `walk()` the tree created by example 05, print each entry, then `removeDirectoryTree()` to wipe it. |
| 07 | [`07-stream-from-s3.php`](07-stream-from-s3.php) | Seed minio with a payload, `fopen` its public HTTP URL, pipe the stream into `uploadStream()`. The same pattern works with `\Aws\S3\S3Client->getObject()->get('Body')->detach()`. |

## Running

```bash
php examples/01-basic.php
php examples/02-progress.php
# … etc
```

You can also chain them — examples 05 → 06 share a tree (05 creates it,
06 walks + removes it). Run in number order for the cleanest demo.

## Bypassing host-key checks

All examples skip host-key pinning to keep them short. **Don't copy
that pattern into production.** A real client should set
`expectedFingerprint` AND/OR `knownHostsFile` on `connect()` — see the
[Host-key fingerprint verification](../README.md#host-key-fingerprint-verification)
section of the main README.
