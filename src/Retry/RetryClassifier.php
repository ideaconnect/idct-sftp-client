<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Retry;

use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;

/**
 * Stateless allow-list of which {@see SshException} subclasses the
 * client treats as retryable.
 *
 * The retry loop itself lives on {@see \IDCT\Networking\Ssh\SftpClient}
 * because it owns the session state needed for lazy reconnect; this
 * helper just answers the in-principle "can this exception be retried?"
 * question so the loop can short-circuit before consulting the policy.
 *
 * ## Hard NEVER
 *
 * - {@see ConfigurationException} / {@see InvalidPathException}:
 *   caller bug. Retrying executes the same wrong call again.
 * - {@see AuthenticationException}: retrying password-rejected attempts
 *   is how IP bans get earned.
 *
 * ## Retryable
 *
 * - Any {@see ConnectionException}: transport-level, generally transient.
 * - {@see TransferException} whose message contains a known transient
 *   fragment (see {@see self::RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS}).
 *
 * Everything else is treated as permanent — better to error visibly
 * than to mask a real bug behind a retry loop.
 */
final class RetryClassifier
{
    /**
     * Transient-failure substrings inside `TransferException::getMessage()`
     * that the client treats as retryable in addition to all
     * `ConnectionException` failures.
     *
     * Message-matching is the pragmatic compromise: we can't introduce a
     * new exception subtype per transient cause without breaking the
     * single-root hierarchy contract, and the messages themselves are
     * stable strings produced by `SftpClient`. Anything not on this list
     * is treated as permanent (caller error, real filesystem state) and
     * propagated immediately.
     *
     * @var list<string>
     */
    public const RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS = [
        'Failed to copy',
        'Unable to open remote',
        'Could not SCP-download',
        'Could not SCP-upload',
    ];

    /**
     * Return `true` when the retry loop should consult the policy for
     * `$e`; `false` to propagate immediately.
     */
    public static function isRetryable(SshException $e): bool
    {
        if ($e instanceof InvalidPathException) {
            return false;
        }
        if ($e instanceof ConfigurationException) {
            return false;
        }
        if ($e instanceof AuthenticationException) {
            return false;
        }
        if ($e instanceof ConnectionException) {
            return true;
        }
        if ($e instanceof TransferException) {
            $msg = $e->getMessage();
            foreach (self::RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS as $fragment) {
                if (str_contains($msg, $fragment)) {
                    return true;
                }
            }
        }

        return false;
    }
}
