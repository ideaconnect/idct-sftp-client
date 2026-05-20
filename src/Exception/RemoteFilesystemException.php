<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * SFTP-level filesystem operation failed: stat / mkdir / rmdir / rename /
 * unlink / readdir against a remote path the server rejected.
 */
final class RemoteFilesystemException extends SshException {}
