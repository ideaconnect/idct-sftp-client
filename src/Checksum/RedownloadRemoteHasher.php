<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Checksum;

use IDCT\Networking\Ssh\SftpClient;

/**
 * Last-resort remote hasher for environments without shell access: opens
 * a fresh SFTP read stream for `$remotePath` and hashes the bytes as
 * they arrive. Doubles the cost of an upload+verify cycle (the file is
 * sent up once and pulled back down for verification), so it's only
 * worth using when {@see ShellSumRemoteHasher} can't be deployed.
 *
 * Chunk size is borrowed from the client so very large files don't
 * load entirely into memory.
 */
final class RedownloadRemoteHasher implements RemoteHasherInterface
{
    /**
     * @param string $algorithm Any algorithm name accepted by `hash_init()`
     *        (`sha256`, `sha1`, `md5`, `xxh64`, …). Defaults to `sha256`.
     *        SftpClient cross-checks this against `hash_file()` on the
     *        local side, so make sure both sides agree on the name.
     */
    public function __construct(
        public readonly string $algorithm = 'sha256',
    ) {}

    /** {@inheritDoc} */
    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Stream the remote file via {@see SftpClient::downloadStream()}
     * into a `php://temp` sink, then hash the sink in one C-level
     * `hash_update_stream` call. Lowercase-hex digest.
     *
     * @throws \IDCT\Networking\Ssh\Exception\TransferException
     *         if downloadStream itself fails (propagated unchanged
     *         from SftpClient).
     */
    public function hash(SftpClient $client, string $remotePath): string
    {
        // Stream the remote file into a temp sink via downloadStream, then
        // let PHP's hash_update_stream consume the whole sink in C — no
        // manual fread loop means no defensive empty/false branches.
        // php://temp/maxmemory:0 spills to disk immediately; the same call
        // is documented to not return false in practice (failure modes
        // would also break fopen on a regular file). Catching it here
        // would be belt-and-braces with nothing to do beyond rethrow.
        $sink = fopen('php://temp/maxmemory:0', 'r+b');
        \assert($sink !== false);

        try {
            $client->downloadStream($remotePath, $sink);
            rewind($sink);
            $ctx = hash_init($this->algorithm);
            hash_update_stream($ctx, $sink);

            return strtolower(hash_final($ctx));
        } finally {
            fclose($sink);
        }
    }
}
