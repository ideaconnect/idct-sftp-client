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
    /** Regular file (mode bits `S_IFREG` = `0o100000`). Carries a size. */
    case File;

    /** Directory (mode bits `S_IFDIR` = `0o040000`). Recursable; no size. */
    case Directory;

    /**
     * Symbolic link (mode bits `S_IFLNK` = `0o120000`). NOT followed by
     * {@see \IDCT\Networking\Ssh\SftpClient::walk()} — the symlink itself
     * is yielded as an entry; callers decide what to do with it.
     */
    case Symlink;

    /**
     * Catch-all for entry types we don't recognise (socket / FIFO /
     * block / character device) or when the server's stat failed and
     * we couldn't classify the entry at all. Walk still yields these
     * so iteration doesn't silently drop them.
     */
    case Other;
}
