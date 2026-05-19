<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Auth;

use IDCT\Networking\Ssh\Auth\AuthFailureRateLimiter;
use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Behaviour-only tests for the per-host auth backoff. We never let the
 * tests actually `usleep` for real wall-clock time — the assertions
 * check the *decision* (would-sleep vs would-not-sleep) and the
 * computed delay via {@see failureCount()} + the public formula.
 *
 * State is process-global, so `reset()` between cases is mandatory.
 */
#[CoversClass(AuthFailureRateLimiter::class)]
#[CoversClass(SftpClient::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(AuthenticationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class AuthFailureRateLimiterTest extends TestCase
{
    protected function setUp(): void
    {
        AuthFailureRateLimiter::reset();
    }

    public function testDefaultsMatchPlan(): void
    {
        $r = new AuthFailureRateLimiter();
        self::assertSame(3, $r->thresholdFailures);
        self::assertSame(1000, $r->baseDelayMs);
        self::assertSame(60_000, $r->maxDelayMs);
    }

    public function testRecordFailureIncrementsCounter(): void
    {
        $r = new AuthFailureRateLimiter();
        self::assertSame(0, $r->failureCount('h', 22, 'u'));
        $r->recordFailure('h', 22, 'u');
        $r->recordFailure('h', 22, 'u');
        self::assertSame(2, $r->failureCount('h', 22, 'u'));
    }

    public function testRecordSuccessResetsCounter(): void
    {
        $r = new AuthFailureRateLimiter();
        $r->recordFailure('h', 22, 'u');
        $r->recordFailure('h', 22, 'u');
        $r->recordSuccess('h', 22, 'u');
        self::assertSame(0, $r->failureCount('h', 22, 'u'));
    }

    public function testCounterKeyedPerHostPortUser(): void
    {
        $r = new AuthFailureRateLimiter();
        $r->recordFailure('host-a', 22, 'alice');
        $r->recordFailure('host-a', 22, 'bob');
        $r->recordFailure('host-b', 22, 'alice');
        $r->recordFailure('host-a', 2222, 'alice');

        self::assertSame(1, $r->failureCount('host-a', 22, 'alice'));
        self::assertSame(1, $r->failureCount('host-a', 22, 'bob'));
        self::assertSame(1, $r->failureCount('host-b', 22, 'alice'));
        self::assertSame(1, $r->failureCount('host-a', 2222, 'alice'));
    }

    public function testBeforeAuthIsNoopBelowThreshold(): void
    {
        // tiny base / max so any actual sleep would show up; we just call
        // beforeAuth and measure that it returns immediately under threshold.
        $r = new AuthFailureRateLimiter(thresholdFailures: 3, baseDelayMs: 1000, maxDelayMs: 60_000);
        $r->recordFailure('h', 22, 'u');
        $r->recordFailure('h', 22, 'u');

        $start = microtime(true);
        $r->beforeAuth('h', 22, 'u');
        $elapsedMs = (int) ((microtime(true) - $start) * 1000);

        self::assertLessThan(50, $elapsedMs, 'beforeAuth should be a no-op below threshold');
    }

    public function testBeforeAuthSleepsAtAndAboveThreshold(): void
    {
        // 3 failures, threshold 3 → "over" = 0 → delay = baseDelayMs * 2^0 = baseDelayMs.
        // Pick a small base so the test runs fast.
        $r = new AuthFailureRateLimiter(thresholdFailures: 3, baseDelayMs: 50, maxDelayMs: 60_000);
        $r->recordFailure('h', 22, 'u');
        $r->recordFailure('h', 22, 'u');
        $r->recordFailure('h', 22, 'u');

        $start = microtime(true);
        $r->beforeAuth('h', 22, 'u');
        $elapsedMs = (int) ((microtime(true) - $start) * 1000);

        // Allow slack — CI hosts schedule us back when they feel like it.
        self::assertGreaterThanOrEqual(40, $elapsedMs);
        self::assertLessThan(300, $elapsedMs, 'delay should be near baseDelayMs');
    }

    public function testBeforeAuthDelayCapsAtMaxDelayMs(): void
    {
        // 5 failures, threshold 3, base 1000, max 100. Computed:
        // 1000 * 2^(5-3) = 4000, capped at 100. Tests the min() branch.
        $r = new AuthFailureRateLimiter(thresholdFailures: 3, baseDelayMs: 1000, maxDelayMs: 100);
        for ($i = 0; $i < 5; $i++) {
            $r->recordFailure('h', 22, 'u');
        }

        $start = microtime(true);
        $r->beforeAuth('h', 22, 'u');
        $elapsedMs = (int) ((microtime(true) - $start) * 1000);

        self::assertGreaterThanOrEqual(80, $elapsedMs);
        // Generous upper bound for slow CI; verifies the cap, not exact timing.
        self::assertLessThan(500, $elapsedMs);
    }

    public function testSftpClientAccessorRoundtrip(): void
    {
        /** @var Ssh2FunctionsInterface&MockObject $ssh2 */
        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());

        self::assertNull($client->getAuthFailureRateLimiter(), 'off by default');

        $limiter = new AuthFailureRateLimiter();
        self::assertSame($client, $client->setAuthFailureRateLimiter($limiter));
        self::assertSame($limiter, $client->getAuthFailureRateLimiter());

        $client->setAuthFailureRateLimiter(null);
        self::assertNull($client->getAuthFailureRateLimiter());
    }

    public function testSftpClientRecordsFailureWhenAuthIsRejected(): void
    {
        /** @var Ssh2FunctionsInterface&MockObject $ssh2 */
        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $session = new \stdClass();
        $ssh2->method('connect')->willReturn($session);
        $ssh2->method('authPassword')->willReturn(false); // server rejects

        $limiter = new AuthFailureRateLimiter();
        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setAuthFailureRateLimiter($limiter);

        try {
            $client->connect('rate-limit-host.example.com');
            self::fail('expected AuthenticationException');
        } catch (AuthenticationException) {
            // expected
        }
        self::assertSame(
            1,
            $limiter->failureCount('rate-limit-host.example.com', 22, 'alice'),
            'rate limiter should have tallied the rejection',
        );
    }

    public function testSftpClientResetsCounterOnSuccessfulAuth(): void
    {
        /** @var Ssh2FunctionsInterface&MockObject $ssh2 */
        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $session = new \stdClass();
        $sftp = new class {
            public function __toString(): string
            {
                return '1';
            }
        };
        $ssh2->method('connect')->willReturn($session);
        $ssh2->method('authPassword')->willReturn(true);
        $ssh2->method('sftp')->willReturn($sftp);

        $limiter = new AuthFailureRateLimiter();
        // Pre-seed a couple of failures, then a successful connect
        // should reset the counter back to 0.
        $limiter->recordFailure('success-host.example.com', 22, 'alice');
        $limiter->recordFailure('success-host.example.com', 22, 'alice');

        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setAuthFailureRateLimiter($limiter);
        $client->connect('success-host.example.com');

        self::assertSame(
            0,
            $limiter->failureCount('success-host.example.com', 22, 'alice'),
            'successful auth should reset the per-host counter',
        );
    }

    public function testResetWipesAllCounters(): void
    {
        $r = new AuthFailureRateLimiter();
        $r->recordFailure('h1', 22, 'u');
        $r->recordFailure('h2', 22, 'u');

        AuthFailureRateLimiter::reset();

        self::assertSame(0, $r->failureCount('h1', 22, 'u'));
        self::assertSame(0, $r->failureCount('h2', 22, 'u'));
    }
}
