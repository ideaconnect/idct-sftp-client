<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * How {@see \IDCT\Networking\Ssh\SftpClient::uploadDirectory()} and
 * {@see \IDCT\Networking\Ssh\SftpClient::downloadDirectory()} react when
 * a destination file already exists.
 *
 * Directory entries are unaffected: pre-existing directories are always
 * reused (we mkdir if missing, otherwise descend in). Files are the
 * configurable part.
 */
enum ConflictPolicy
{
    /**
     * Existing destination files are silently replaced. Default — atomic
     * rename does this naturally on the upload side, and the local
     * `wb` fopen truncates on the download side.
     */
    case Overwrite;

    /**
     * Existing destination files are left as-is; the per-file transfer
     * is skipped and the source path is recorded in
     * {@see UploadResult::$skipped} / {@see DownloadResult::$skipped}.
     */
    case Skip;

    /**
     * Existing destination files cause the operation to abort with a
     * {@see \IDCT\Networking\Ssh\Exception\RemoteFilesystemException}
     * (on upload) or {@see \IDCT\Networking\Ssh\Exception\ConfigurationException}
     * (on download — the local file is the caller's problem, not the
     * server's). Suitable for one-shot deployments that must never
     * clobber.
     */
    case Fail;
}
