<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Retry;

use IDCT\Networking\Ssh\Exception\SshException;

/**
 * Opt-out policy: every failure is propagated immediately, no retries.
 *
 * Useful when you want the pre-P5 one-shot behaviour back (e.g., when an
 * outer retry layer in your application is the source of truth) or in
 * tests that want determinism without faking timing.
 */
final class NoRetryPolicy implements RetryPolicyInterface
{
    public function nextDelayMs(int $attempt, SshException $lastError): int
    {
        return 0;
    }
}
