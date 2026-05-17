<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(FingerprintEncoding::class)]
final class FingerprintEncodingTest extends TestCase
{
    public function testValuesMatchSsh2Flags(): void
    {
        self::assertSame(0, FingerprintEncoding::Hex->value);
        self::assertSame(2, FingerprintEncoding::Raw->value);
    }
}
