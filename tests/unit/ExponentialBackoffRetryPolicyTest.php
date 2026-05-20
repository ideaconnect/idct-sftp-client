<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ExponentialBackoffRetryPolicy::class)]
#[UsesClass(ConnectionException::class)]
#[UsesClass(SshException::class)]
final class ExponentialBackoffRetryPolicyTest extends TestCase
{
    private function err(): SshException
    {
        return new ConnectionException('test');
    }

    // ─── construction / validation ─────────────────────────────────────

    public function testDefaultsMatchPlan(): void
    {
        $p = new ExponentialBackoffRetryPolicy();
        self::assertSame(5, $p->maxRetries);
        self::assertSame(200, $p->baseMs);
        self::assertSame(30_000, $p->maxMs);
        self::assertSame(0.3, $p->jitter);
    }

    public function testRejectsZeroMaxRetries(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('NoRetryPolicy');
        new ExponentialBackoffRetryPolicy(maxRetries: 0);
    }

    public function testAcceptsMaxRetriesOfExactlyOne(): void
    {
        // Boundary: the guard reads `< 1`, so 1 must construct cleanly.
        // Kills the `$maxRetries < 1` → `<= 1` mutant which would
        // wrongly reject 1.
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 1);
        self::assertSame(1, $p->maxRetries);
    }

    public function testRejectsNegativeBaseMs(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new ExponentialBackoffRetryPolicy(baseMs: -1);
    }

    public function testAcceptsBaseMsOfExactlyZero(): void
    {
        // Boundary: the guard is `< 0`, so 0 must construct. baseMs=0
        // is a legitimate "no minimum delay" choice. Kills the
        // `$baseMs < 0` → `<= 0` mutant.
        $p = new ExponentialBackoffRetryPolicy(baseMs: 0, maxMs: 1000);
        self::assertSame(0, $p->baseMs);
    }

    public function testAcceptsMaxMsOfExactlyZero(): void
    {
        // Boundary: the guard is `< 0`, so 0 must construct. maxMs=0
        // means "never wait" which combined with baseMs=0 is a
        // degenerate-but-valid configuration. Kills the
        // `$maxMs < 0` → `<= 0` mutant.
        $p = new ExponentialBackoffRetryPolicy(baseMs: 0, maxMs: 0);
        self::assertSame(0, $p->maxMs);
    }

    public function testRejectsBaseGreaterThanMax(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot exceed');
        new ExponentialBackoffRetryPolicy(baseMs: 10_000, maxMs: 5_000);
    }

    /**
     * @return iterable<string, array{float}>
     */
    public static function badJitter(): iterable
    {
        yield 'negative' => [-0.1];
        yield 'over one' => [1.1];
    }

    #[DataProvider('badJitter')]
    public function testRejectsOutOfBoundsJitter(float $j): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('jitter');
        new ExponentialBackoffRetryPolicy(jitter: $j);
    }

    // ─── delay math (deterministic when jitter=0) ──────────────────────

    /**
     * @return iterable<string, array{int, int}> attempt → expected ms
     */
    public static function deterministicDelays(): iterable
    {
        // base=100, max=10_000, jitter=0
        // attempt 1: 100 * 2^0 = 100
        // attempt 2: 100 * 2^1 = 200
        // attempt 3: 100 * 2^2 = 400
        // attempt 4: 100 * 2^3 = 800
        // attempt 5: 100 * 2^4 = 1600
        yield 'a=1' => [1, 100];
        yield 'a=2' => [2, 200];
        yield 'a=3' => [3, 400];
        yield 'a=4' => [4, 800];
        yield 'a=5' => [5, 1600];
    }

    #[DataProvider('deterministicDelays')]
    public function testDeterministicExponentialGrowth(int $attempt, int $expected): void
    {
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 5, baseMs: 100, maxMs: 10_000, jitter: 0.0);
        self::assertSame($expected, $p->nextDelayMs($attempt, $this->err()));
    }

    public function testCapsAtMaxMs(): void
    {
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 10, baseMs: 100, maxMs: 500, jitter: 0.0);
        // 100, 200, 400, then capped at 500
        self::assertSame(500, $p->nextDelayMs(4, $this->err()));
        self::assertSame(500, $p->nextDelayMs(10, $this->err()));
    }

    public function testReturnsZeroAfterMaxRetries(): void
    {
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 3);
        self::assertGreaterThan(0, $p->nextDelayMs(3, $this->err()));
        self::assertSame(0, $p->nextDelayMs(4, $this->err()));
        self::assertSame(0, $p->nextDelayMs(99, $this->err()));
    }

    public function testJitterStaysWithinBounds(): void
    {
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 5, baseMs: 1000, maxMs: 10_000, jitter: 0.5);
        // deterministic part at attempt 1 = 1000; jitter 0.5 means ±500.
        // So result must be in [500, 1500].
        for ($i = 0; $i < 100; $i++) {
            $delay = $p->nextDelayMs(1, $this->err());
            self::assertGreaterThanOrEqual(500, $delay, "iteration $i: $delay");
            self::assertLessThanOrEqual(1500, $delay, "iteration $i: $delay");
        }
    }

    public function testJitterNeverExceedsMaxMsHardCap(): void
    {
        // Set base==max so jitter could push above max — the policy must clamp.
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 5, baseMs: 1000, maxMs: 1000, jitter: 1.0);
        for ($i = 0; $i < 100; $i++) {
            self::assertLessThanOrEqual(1000, $p->nextDelayMs(1, $this->err()));
        }
    }

    public function testJitterNeverBelowZero(): void
    {
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 5, baseMs: 10, maxMs: 100, jitter: 1.0);
        for ($i = 0; $i < 100; $i++) {
            self::assertGreaterThanOrEqual(0, $p->nextDelayMs(1, $this->err()));
        }
    }

    public function testHighAttemptDoesNotOverflowInt(): void
    {
        // Sanity: at attempt=30+, 2^attempt overflows int but we cap exponent at 30
        // and the result is bounded by maxMs anyway.
        $p = new ExponentialBackoffRetryPolicy(maxRetries: 100, baseMs: 1, maxMs: 1000, jitter: 0.0);
        self::assertSame(1000, $p->nextDelayMs(50, $this->err()));
    }
}
