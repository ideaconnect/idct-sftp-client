<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Auth;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Auth\CredentialsInterface;
use IDCT\Networking\Ssh\Auth\StaticCredentialsLoader;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(StaticCredentialsLoader::class)]
#[CoversClass(SftpClient::class)]
#[UsesClass(\IDCT\Networking\Ssh\Auth\AuthDispatcher::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class CredentialsLoaderTest extends TestCase
{
    public function testStaticLoaderReturnsSameInstanceRegardlessOfHost(): void
    {
        $creds = Credentials::withPassword('alice', 'secret');
        $loader = new StaticCredentialsLoader($creds);

        self::assertSame($creds, $loader->load('example.com'));
        self::assertSame($creds, $loader->load('any.other.host'));
    }

    public function testSftpClientUsesLoaderWhenNoExplicitCredentialsSet(): void
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

        $loader = new StaticCredentialsLoader(Credentials::withPassword('alice', 'secret'));

        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        self::assertSame($client, $client->setCredentialsLoader($loader));
        self::assertSame($loader, $client->getCredentialsLoader());
        self::assertNull($client->getCredentials(), 'loader installed → no cached explicit credentials yet');

        $client->connect('host-a.example.com');

        // After connect(), credentials should have been resolved via the loader.
        $resolved = $client->getCredentials();
        self::assertInstanceOf(CredentialsInterface::class, $resolved);
        self::assertSame('alice', $resolved->getUsername());
    }

    public function testSetCredentialsClearsAnyPreviouslyInstalledLoader(): void
    {
        /** @var Ssh2FunctionsInterface&MockObject $ssh2 */
        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());

        $client->setCredentialsLoader(
            new StaticCredentialsLoader(Credentials::withPassword('via-loader', 'x')),
        );
        $explicit = Credentials::withPassword('via-explicit', 'y');
        $client->setCredentials($explicit);

        self::assertSame($explicit, $client->getCredentials());
        self::assertNull(
            $client->getCredentialsLoader(),
            'setCredentials() must clear the loader so resolution is unambiguous',
        );
    }

    public function testSetCredentialsLoaderClearsExplicitCredentials(): void
    {
        /** @var Ssh2FunctionsInterface&MockObject $ssh2 */
        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());

        $client->setCredentials(Credentials::withPassword('first', 'x'));
        $loader = new StaticCredentialsLoader(Credentials::withPassword('via-loader', 'y'));
        $client->setCredentialsLoader($loader);

        self::assertNull(
            $client->getCredentials(),
            'setCredentialsLoader() must clear explicit credentials',
        );
        self::assertSame($loader, $client->getCredentialsLoader());
    }
}
