<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * Outcome of a recursive upload. Returned by
 * {@see \IDCT\Networking\Ssh\SftpClient::uploadDirectory()}.
 *
 * `skipped` lists absolute local paths that were intentionally not
 * transferred — currently only symlinks (skip-by-default in 1.1). When
 * opt-in symlink following lands, the same array surfaces broken links
 * and over-depth links.
 */
final readonly class UploadResult
{
    /**
     * @param int<0, max> $filesTransferred
     * @param int<0, max> $bytesTransferred
     * @param list<string> $skipped Absolute LOCAL paths the iteration intentionally bypassed.
     */
    public function __construct(
        public int $filesTransferred,
        public int $bytesTransferred,
        public array $skipped = [],
    ) {}
}
