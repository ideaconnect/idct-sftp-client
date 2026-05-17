<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * Outcome of a recursive download. Returned by
 * {@see \IDCT\Networking\Ssh\SftpClient::downloadDirectory()}.
 *
 * `skipped` lists absolute REMOTE paths that were intentionally not
 * transferred — currently only symlinks (skip-by-default in 1.1).
 */
final readonly class DownloadResult
{
    /**
     * @param int<0, max> $filesTransferred
     * @param int<0, max> $bytesTransferred
     * @param list<string> $skipped Absolute REMOTE paths the iteration intentionally bypassed.
     */
    public function __construct(
        public int $filesTransferred,
        public int $bytesTransferred,
        public array $skipped = [],
    ) {}
}
