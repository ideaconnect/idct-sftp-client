<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(NoRetryPolicy::class)]
#[UsesClass(ConnectionException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class NoRetryPolicyTest extends TestCase
{
    public function testAlwaysReturnsZero(): void
    {
        $p = new NoRetryPolicy();
        $err = new ConnectionException('whatever');

        for ($attempt = 1; $attempt <= 100; $attempt++) {
            self::assertSame(0, $p->nextDelayMs($attempt, $err));
        }
    }
}
