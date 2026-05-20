<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * Immutable description of a single entry yielded by
 * {@see \IDCT\Networking\Ssh\SftpClient::walk()}.
 */
final readonly class RemoteEntry
{
    /**
     * @param string $path Absolute remote path of the entry.
     * @param EntryType $type Regular file, directory, symlink, or "other" (devices/FIFOs).
     * @param int<0, max>|null $size Bytes for regular files; null for everything else.
     */
    public function __construct(
        public string $path,
        public EntryType $type,
        public ?int $size = null,
    ) {}
}
