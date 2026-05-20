<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Auth;

use IDCT\Networking\Ssh\Auth\AuthDispatcher;
use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Direct unit tests for the auth-mode dispatcher. SftpClient wires this
 * into `connect()`, but the integration tests over there can only
 * exercise one mode per scenario — and `LoggerIntegrationTest` only
 * covers the Password path. This file walks every match arm:
 *
 *  - None     → ssh2_auth_none
 *  - Password → ssh2_auth_password
 *  - PublicKey → ssh2_auth_pubkey_file
 *  - Both     → both ssh2_auth_pubkey_file AND ssh2_auth_password
 *               must return true
 *
 * plus the rejection paths (each returning false) so the dispatcher's
 * boolean return surface is locked down.
 */
#[CoversClass(AuthDispatcher::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
final class AuthDispatcherTest extends TestCase
{
    private string $pubKey;
    private string $privKey;

    protected function setUp(): void
    {
        // Real key files so Credentials::withPublicKey() / withBoth()
        // pass their existence validation. Content is irrelevant to the
        // dispatcher — it just hands the paths through to ssh2 mocks.
        $tmp = sys_get_temp_dir() . '/idct-auth-dispatch-' . bin2hex(random_bytes(4));
        mkdir($tmp);
        $this->pubKey = $tmp . '/id_rsa.pub';
        $this->privKey = $tmp . '/id_rsa';
        file_put_contents($this->pubKey, 'pub');
        file_put_contents($this->privKey, 'priv');
    }

    protected function tearDown(): void
    {
        @unlink($this->pubKey);
        @unlink($this->privKey);
        @rmdir(\dirname($this->pubKey));
    }

    public function testNoneModeCallsAuthNone(): void
    {
        $ssh2 = $this->ssh2();
        $session = new \stdClass();
        $ssh2->expects(self::once())
            ->method('authNone')
            ->with($session, 'guest')
            ->willReturn(true);
        $ssh2->expects(self::never())->method('authPassword');
        $ssh2->expects(self::never())->method('authPublicKey');

        self::assertTrue(AuthDispatcher::dispatch($session, Credentials::withNone('guest'), $ssh2));
    }

    public function testNoneModeReturnsFalseWhenServerRejects(): void
    {
        $ssh2 = $this->ssh2();
        $ssh2->method('authNone')->willReturn(false);

        self::assertFalse(
            AuthDispatcher::dispatch(new \stdClass(), Credentials::withNone('guest'), $ssh2),
        );
    }

    public function testPasswordModeCallsAuthPassword(): void
    {
        $ssh2 = $this->ssh2();
        $session = new \stdClass();
        $ssh2->expects(self::once())
            ->method('authPassword')
            ->with($session, 'alice', 'secret')
            ->willReturn(true);
        $ssh2->expects(self::never())->method('authPublicKey');
        $ssh2->expects(self::never())->method('authNone');

        self::assertTrue(
            AuthDispatcher::dispatch($session, Credentials::withPassword('alice', 'secret'), $ssh2),
        );
    }

    public function testPasswordModeReturnsFalseWhenServerRejects(): void
    {
        $ssh2 = $this->ssh2();
        $ssh2->method('authPassword')->willReturn(false);

        self::assertFalse(
            AuthDispatcher::dispatch(
                new \stdClass(),
                Credentials::withPassword('alice', 'wrong'),
                $ssh2,
            ),
        );
    }

    public function testPublicKeyModeCallsAuthPublicKey(): void
    {
        $ssh2 = $this->ssh2();
        $session = new \stdClass();
        $ssh2->expects(self::once())
            ->method('authPublicKey')
            ->with($session, 'bob', $this->pubKey, $this->privKey, 'phrase')
            ->willReturn(true);
        $ssh2->expects(self::never())->method('authPassword');
        $ssh2->expects(self::never())->method('authNone');

        $creds = Credentials::withPublicKey('bob', $this->pubKey, $this->privKey, 'phrase');
        self::assertTrue(AuthDispatcher::dispatch($session, $creds, $ssh2));
    }

    public function testPublicKeyModeReturnsFalseWhenServerRejects(): void
    {
        $ssh2 = $this->ssh2();
        $ssh2->method('authPublicKey')->willReturn(false);

        $creds = Credentials::withPublicKey('bob', $this->pubKey, $this->privKey);
        self::assertFalse(AuthDispatcher::dispatch(new \stdClass(), $creds, $ssh2));
    }

    public function testBothModeRequiresPubkeyAndPasswordToSucceed(): void
    {
        $ssh2 = $this->ssh2();
        $session = new \stdClass();
        $ssh2->expects(self::once())
            ->method('authPublicKey')
            ->with($session, 'carol', $this->pubKey, $this->privKey, null)
            ->willReturn(true);
        $ssh2->expects(self::once())
            ->method('authPassword')
            ->with($session, 'carol', 'pw')
            ->willReturn(true);

        $creds = Credentials::withBoth('carol', 'pw', $this->pubKey, $this->privKey);
        self::assertTrue(AuthDispatcher::dispatch($session, $creds, $ssh2));
    }

    public function testBothModeFailsWhenPubkeyLegFails(): void
    {
        $ssh2 = $this->ssh2();
        $ssh2->method('authPublicKey')->willReturn(false);
        // password leg STILL runs (the dispatcher doesn't short-circuit
        // on pubkey-fail — both calls happen and the AND combines them).
        // That's deliberate: short-circuiting would leak which leg
        // failed via timing.
        $ssh2->method('authPassword')->willReturn(true);

        $creds = Credentials::withBoth('carol', 'pw', $this->pubKey, $this->privKey);
        self::assertFalse(AuthDispatcher::dispatch(new \stdClass(), $creds, $ssh2));
    }

    public function testBothModeFailsWhenPasswordLegFails(): void
    {
        $ssh2 = $this->ssh2();
        $ssh2->method('authPublicKey')->willReturn(true);
        $ssh2->method('authPassword')->willReturn(false);

        $creds = Credentials::withBoth('carol', 'wrong', $this->pubKey, $this->privKey);
        self::assertFalse(AuthDispatcher::dispatch(new \stdClass(), $creds, $ssh2));
    }

    /** @return Ssh2FunctionsInterface&MockObject */
    private function ssh2(): Ssh2FunctionsInterface
    {
        return $this->createMock(Ssh2FunctionsInterface::class);
    }
}
