<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Retry;

use IDCT\Networking\Ssh\Exception\SshException;

/**
 * Default {@see RetryPolicyInterface} implementation: capped exponential
 * backoff with multiplicative jitter.
 *
 * Math: delay = min(maxMs, baseMs * 2^(attempt-1)), then perturbed by ±jitter
 * fraction (uniform). Returns 0 once `$attempt` exceeds `$maxRetries`,
 * which is the policy's only way to signal "give up" to the client.
 *
 * `$attempt` is the retry number (1 = first retry, after the initial
 * failure), matching the contract on {@see RetryPolicyInterface}.
 */
final class ExponentialBackoffRetryPolicy implements RetryPolicyInterface
{
    /**
     * Property types are kept as plain `int` (not constrained `int<1, max>`)
     * so the runtime guards below remain reachable from PHPStan's view: a
     * tighter phpdoc bound would render the validation dead code.
     *
     * @param int $maxRetries number of retries to allow before giving up
     *                        (default 5 → up to 6 total attempts incl. the original)
     * @param int $baseMs the delay before the first retry
     * @param int $maxMs upper bound after exponential growth + jitter
     * @param float $jitter +/- fraction of the deterministic delay (0.0 = no jitter)
     */
    public function __construct(
        public readonly int $maxRetries = 5,
        public readonly int $baseMs = 200,
        public readonly int $maxMs = 30_000,
        public readonly float $jitter = 0.3,
    ) {
        if ($maxRetries < 1) {
            throw new \InvalidArgumentException('maxRetries must be >= 1; use NoRetryPolicy to disable retries.');
        }
        if ($baseMs < 0 || $maxMs < 0) {
            throw new \InvalidArgumentException('baseMs and maxMs must be non-negative.');
        }
        if ($baseMs > $maxMs) {
            throw new \InvalidArgumentException('baseMs cannot exceed maxMs.');
        }
        if ($jitter < 0.0 || $jitter > 1.0) {
            throw new \InvalidArgumentException('jitter must be between 0.0 and 1.0.');
        }
    }

    public function nextDelayMs(int $attempt, SshException $lastError): int
    {
        if ($attempt > $this->maxRetries) {
            return 0;
        }

        // Cap the exponent so 2^(attempt-1) doesn't overflow int for high attempt counts;
        // we'd be capped by $maxMs anyway, but PHP rejects overflowing left-shifts as floats.
        $exponent = min($attempt - 1, 30);
        $deterministic = min($this->maxMs, $this->baseMs * (2 ** $exponent));

        // Jitter: multiplicative ±jitter fraction. Use mt_rand for unweighted uniform sampling.
        $perturbation = $deterministic * $this->jitter * ((mt_rand() / mt_getrandmax()) * 2 - 1);
        $delay = max(0, (int) round($deterministic + $perturbation));

        // Final hard cap so a positive perturbation never exceeds maxMs.
        // Outer max(0, ...) keeps the int<0, max> return type guaranteed.
        return max(0, min($this->maxMs, $delay));
    }
}
