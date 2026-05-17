<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * Classification used by {@see \IDCT\Networking\Ssh\SftpClient::walk()}
 * and the recursive directory operations.
 *
 * `Other` is the catch-all for SFTP entries that are neither regular files,
 * directories, nor symbolic links (sockets, FIFOs, block/character devices).
 * Real-world SFTP servers expose these rarely; the bucket exists so the
 * iteration doesn't drop unknown entries silently.
 */
enum EntryType
{
    case File;
    case Directory;
    case Symlink;
    case Other;
}
