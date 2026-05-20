<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuthMode::class)]
final class AuthModeTest extends TestCase
{
    /**
     * @return iterable<string, array{AuthMode, bool, bool}>
     */
    public static function modeMatrix(): iterable
    {
        yield 'None'      => [AuthMode::None,      false, false];
        yield 'Password'  => [AuthMode::Password,  true,  false];
        yield 'PublicKey' => [AuthMode::PublicKey, false, true];
        yield 'Both'      => [AuthMode::Both,      true,  true];
    }

    #[DataProvider('modeMatrix')]
    public function testNeedsPasswordAndKeys(AuthMode $mode, bool $needsPassword, bool $needsKeys): void
    {
        self::assertSame($needsPassword, $mode->needsPassword());
        self::assertSame($needsKeys, $mode->needsKeys());
    }

    public function testIntValuesAreStable(): void
    {
        self::assertSame(0, AuthMode::None->value);
        self::assertSame(1, AuthMode::Password->value);
        self::assertSame(2, AuthMode::PublicKey->value);
        self::assertSame(3, AuthMode::Both->value);
    }
}
