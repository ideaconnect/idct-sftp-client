<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Retry;

use IDCT\Networking\Ssh\Exception\SshException;

/**
 * Pluggable strategy for deciding whether (and when) to retry a failed
 * operation against the SFTP server.
 *
 * The client invokes {@see nextDelayMs()} after every failed `connect()`,
 * `upload()`, `download()`, or `scpUpload()`/`scpDownload()` call. The
 * implementation decides whether to wait and try again or give up by
 * returning the next delay in milliseconds (or 0 to abort).
 *
 * ## Contract for implementors
 *
 * - MUST be idempotent and stateless across calls. The client passes the
 *   current attempt number; do not track it internally.
 * - MUST NEVER retry exceptions of type
 *   {@see \IDCT\Networking\Ssh\Exception\AuthenticationException} or
 *   {@see \IDCT\Networking\Ssh\Exception\ConfigurationException} (would
 *   cause IP bans / waste of effort). The default implementation shipped
 *   with `idct/sftp-client` enforces this; custom implementations should
 *   too.
 * - SHOULD add jitter to avoid thundering-herd reconnects.
 * - SHOULD cap delays at a sensible upper bound (the default is 30s).
 */
interface RetryPolicyInterface
{
    /**
     * @param int<1, max> $attempt The current attempt number (1 = first retry, after the initial failure)
     * @param SshException $lastError The exception that triggered this decision
     * @return int<0, max> Milliseconds to wait before the next attempt, or 0 to abort and rethrow
     */
    public function nextDelayMs(int $attempt, SshException $lastError): int;
}
