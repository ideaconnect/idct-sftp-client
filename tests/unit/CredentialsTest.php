<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Auth\CredentialsInterface;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Credentials::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class CredentialsTest extends TestCase
{
    private string $pubKeyFile;
    private string $privKeyFile;

    protected function setUp(): void
    {
        $this->pubKeyFile = tempnam(sys_get_temp_dir(), 'idct-pub-');
        $this->privKeyFile = tempnam(sys_get_temp_dir(), 'idct-priv-');
        file_put_contents($this->pubKeyFile, "ssh-rsa AAAA dummy\n");
        file_put_contents($this->privKeyFile, "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----\n");
    }

    protected function tearDown(): void
    {
        @unlink($this->pubKeyFile);
        @unlink($this->privKeyFile);
    }

    public function testWithPasswordFactory(): void
    {
        $c = Credentials::withPassword('alice', 'secret');
        self::assertSame(AuthMode::Password, $c->mode);
        self::assertSame('alice', $c->username);
        self::assertSame('secret', $c->password);
        self::assertNull($c->publicKey);
        self::assertNull($c->privateKey);
        self::assertNull($c->passphrase);
    }

    public function testWithPublicKeyFactory(): void
    {
        $c = Credentials::withPublicKey('bob', $this->pubKeyFile, $this->privKeyFile, 'phrase');
        self::assertSame(AuthMode::PublicKey, $c->mode);
        self::assertSame('bob', $c->username);
        self::assertNull($c->password);
        self::assertSame($this->pubKeyFile, $c->publicKey);
        self::assertSame($this->privKeyFile, $c->privateKey);
        self::assertSame('phrase', $c->passphrase);
    }

    public function testWithPublicKeyFactoryAllowsNullPassphrase(): void
    {
        $c = Credentials::withPublicKey('bob', $this->pubKeyFile, $this->privKeyFile);
        self::assertNull($c->passphrase);
    }

    public function testWithBothFactory(): void
    {
        $c = Credentials::withBoth('carol', 'pw', $this->pubKeyFile, $this->privKeyFile, null);
        self::assertSame(AuthMode::Both, $c->mode);
        self::assertSame('pw', $c->password);
        self::assertSame($this->pubKeyFile, $c->publicKey);
    }

    public function testWithNoneFactory(): void
    {
        $c = Credentials::withNone('guest');
        self::assertSame(AuthMode::None, $c->mode);
        self::assertSame('guest', $c->username);
        self::assertNull($c->password);
    }

    public function testEmptyUsernameRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Username must be at least 1 character long.');
        Credentials::withPassword('', 'secret');
    }

    public function testMissingPublicKeyFileRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Public key file does not exist');
        Credentials::withPublicKey('alice', '/nonexistent/pub', $this->privKeyFile);
    }

    public function testMissingPrivateKeyFileRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Private key file does not exist');
        Credentials::withPublicKey('alice', $this->pubKeyFile, '/nonexistent/priv');
    }

    // The authorize-dispatch tests live in SftpClientTest. Auth dispatch
    // moved off Credentials and onto SftpClient::authorize() so the
    // CredentialsInterface contract stays pure-data, ext-ssh2-free
    // (custom credential sources must not require ext-ssh2 to load).

    public function testImplementsCredentialsInterface(): void
    {
        self::assertInstanceOf(CredentialsInterface::class, Credentials::withNone('g'));
    }

    public function testGettersForwardToProperties(): void
    {
        $c = Credentials::withBoth('carol', 'pw', $this->pubKeyFile, $this->privKeyFile, 'pp');
        self::assertSame(AuthMode::Both, $c->getMode());
        self::assertSame('carol', $c->getUsername());
        self::assertSame('pw', $c->getPassword());
        self::assertSame($this->pubKeyFile, $c->getPublicKey());
        self::assertSame($this->privKeyFile, $c->getPrivateKey());
        self::assertSame('pp', $c->getPassphrase());
    }

    public function testGettersReturnNullWhereAppropriate(): void
    {
        $c = Credentials::withNone('guest');
        self::assertNull($c->getPassword());
        self::assertNull($c->getPublicKey());
        self::assertNull($c->getPrivateKey());
        self::assertNull($c->getPassphrase());
    }

    public function testDebugInfoRedactsSensitiveFields(): void
    {
        $c = Credentials::withBoth('carol', 'super-secret', $this->pubKeyFile, $this->privKeyFile, 'pp');
        $dump = print_r($c, true);
        self::assertStringNotContainsString('super-secret', $dump);
        self::assertStringNotContainsString('pp', $dump);
        self::assertStringContainsString('***REDACTED***', $dump);
        // non-sensitive fields remain visible
        self::assertStringContainsString('carol', $dump);
    }

    public function testDebugInfoNullsStaySafeForPasswordlessModes(): void
    {
        $info = (new \ReflectionMethod(Credentials::class, '__debugInfo'))
            ->invoke(Credentials::withNone('guest'));
        self::assertSame(['mode' => 'None', 'username' => 'guest', 'password' => null, 'publicKey' => null, 'privateKey' => null, 'passphrase' => null], $info);
    }
}
