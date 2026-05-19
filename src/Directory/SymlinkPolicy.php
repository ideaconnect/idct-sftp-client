<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * How {@see \IDCT\Networking\Ssh\SftpClient::uploadDirectory()} /
 * {@see \IDCT\Networking\Ssh\SftpClient::downloadDirectory()} treat
 * symbolic links inside the walked tree.
 *
 * Default {@see self::Skip} matches the original 1.1 behaviour — the
 * safest choice when you don't know what the symlinks point at.
 * `Follow` opts into traversal with inode-based cycle detection (the
 * `(dev, ino)` pair of each visited entry is tracked; a cycle aborts
 * the descent into that branch and records the loop in the result's
 * `skipped` list).
 */
enum SymlinkPolicy
{
    /**
     * Symlinks are skipped and their source paths recorded in the
     * result's `skipped` array. The walk does not descend into a
     * symlinked directory even if its target is a regular dir.
     */
    case Skip;

    /**
     * Symlinks are followed:
     * - A symlink to a regular file is uploaded/downloaded as the
     *   target's contents.
     * - A symlink to a directory is recursed into, with cycle
     *   detection by `(dev, ino)`. A previously-visited inode is
     *   recorded in `skipped` and not re-descended.
     */
    case Follow;
}
