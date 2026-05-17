<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Upload / download / scpUpload / scpDownload failure: remote file missing
 * on download, local file unreadable, stream copy aborted, size or
 * checksum verification mismatch.
 */
final class TransferException extends SshException {}
