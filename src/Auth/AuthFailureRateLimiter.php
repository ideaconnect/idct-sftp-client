<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

/**
 * In-process per-host backoff after consecutive authentication failures.
 *
 * The library's retry policy already hard-blocks auth retries within a
 * single transfer call — `AuthenticationException` is on the never-list
 * in `SftpClient::isRetryable()`. The remaining risk this class
 * addresses is a CALLER that catches the auth exception and re-invokes
 * `connect()` in its own loop, which can trip server-side account
 * lockouts before the human realises something's wrong.
 *
 * After {@see $thresholdFailures} consecutive failures against the
 * same `host:port:user` triple, the next call sleeps for
 * `baseDelayMs * 2^(failures - threshold)` milliseconds, capped at
 * `maxDelayMs`. A single successful auth resets the counter.
 *
 * State is **static** (per PHP process). PHP's request-scoped model
 * means each web request starts fresh — by design, since the alternative
 * is sharing state across unrelated requests through an external store
 * (Redis, file lock). For CLI workers and long-running daemons, the
 * static state covers the entire process lifetime, which is what the
 * plan calls for.
 */
final class AuthFailureRateLimiter
{
    /**
     * Per-process consecutive-failure counts, keyed by
     * `"host:port:user"`. Reset to zero on a successful auth via
     * {@see recordSuccess()} or wholesale via {@see reset()}.
     *
     * @var array<string, int<0, max>>
     */
    private static array $counts = [];

    /**
     * @param int<1, max> $thresholdFailures   how many failures before backoff kicks in
     * @param int<0, max> $baseDelayMs         delay applied at threshold+1
     * @param int<0, max> $maxDelayMs          cap so backoff doesn't grow without bound
     */
    public function __construct(
        public readonly int $thresholdFailures = 3,
        public readonly int $baseDelayMs = 1000,
        public readonly int $maxDelayMs = 60_000,
    ) {}

    /**
     * Called before SftpClient invokes ssh2_auth_*. Sleeps the calling
     * thread if the host has accumulated enough recent failures.
     */
    public function beforeAuth(string $host, int $port, string $user): void
    {
        $key = self::key($host, $port, $user);
        $count = self::$counts[$key] ?? 0;
        if ($count < $this->thresholdFailures) {
            return;
        }

        $over = $count - $this->thresholdFailures;
        $delay = min($this->maxDelayMs, $this->baseDelayMs * (2 ** $over));
        usleep($delay * 1000);
    }

    /**
     * Increment the failure counter for `host:port:user`. SftpClient
     * calls this right before raising `AuthenticationException`.
     */
    public function recordFailure(string $host, int $port, string $user): void
    {
        $key = self::key($host, $port, $user);
        self::$counts[$key] = (self::$counts[$key] ?? 0) + 1;
    }

    /**
     * Reset the failure counter for `host:port:user`. SftpClient calls
     * this right after a successful auth so transient failures don't
     * accumulate forever.
     */
    public function recordSuccess(string $host, int $port, string $user): void
    {
        unset(self::$counts[self::key($host, $port, $user)]);
    }

    /**
     * Read the current consecutive-failure count. Useful for surfacing
     * lockout state in dashboards.
     *
     * @return int<0, max>
     */
    public function failureCount(string $host, int $port, string $user): int
    {
        return self::$counts[self::key($host, $port, $user)] ?? 0;
    }

    /**
     * Wipe every counter. Tests use this between cases; production code
     * usually shouldn't call it (it papers over the very lockout state
     * the limiter exists to enforce).
     */
    public static function reset(): void
    {
        self::$counts = [];
    }

    /**
     * Compose the per-host counter key. Centralised so any future
     * collision-avoidance (e.g. escaping `:` in usernames) lands in
     * one place.
     */
    private static function key(string $host, int $port, string $user): string
    {
        return $host . ':' . $port . ':' . $user;
    }
}
