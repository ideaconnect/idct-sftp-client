<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Checksum;

use IDCT\Networking\Ssh\SftpClient;

/**
 * Pluggable strategy for computing the cryptographic digest of a remote
 * file. Lets {@see SftpClient}'s checksum verification work against any
 * server-side environment — most callers will plug a shell-based
 * implementation (`sha256sum`), but the contract intentionally doesn't
 * mandate one so air-gapped / chroot setups can swap in their own
 * (re-download-and-hash, SFTP server custom extension, etc.).
 *
 * Implementations MUST return:
 *  - the digest as lowercase hex,
 *  - matching {@see algorithm()}'s value,
 *  - computed over the byte stream of `$remotePath`.
 *
 * On failure (binary missing, command error, transient I/O), throw a
 * {@see \IDCT\Networking\Ssh\Exception\TransferException} — that's the
 * class `SftpClient`'s upload/download wrappers will surface to the
 * caller, and the only kind retried per the existing retry rules.
 */
interface RemoteHasherInterface
{
    /**
     * The hash algorithm in `hash()`'s namespace (`sha256`, `sha1`,
     * `md5`, `xxh64`, …). Used by {@see SftpClient} to compute the
     * matching LOCAL hash with `hash_file()` for comparison.
     */
    public function algorithm(): string;

    /**
     * Compute the lowercase-hex digest of `$remotePath` on the server.
     *
     * @throws \IDCT\Networking\Ssh\Exception\TransferException on any failure
     */
    public function hash(SftpClient $client, string $remotePath): string;
}
