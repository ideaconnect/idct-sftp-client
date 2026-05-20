<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(FingerprintAlgorithm::class)]
final class FingerprintAlgorithmTest extends TestCase
{
    public function testValuesMatchSsh2Flags(): void
    {
        self::assertSame(0, FingerprintAlgorithm::Md5->value);
        self::assertSame(1, FingerprintAlgorithm::Sha1->value);
        self::assertSame(2, FingerprintAlgorithm::Sha256->value);
    }
}
