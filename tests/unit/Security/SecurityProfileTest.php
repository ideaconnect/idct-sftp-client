<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Security;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\Security\SecurityProfile;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\CapturingLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[CoversClass(SecurityProfile::class)]
#[CoversClass(SftpClient::class)]
#[UsesClass(\IDCT\Networking\Ssh\Auth\AuthDispatcher::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class SecurityProfileTest extends TestCase
{
    public function testCompatibleProfileReturnsNullMethodsArray(): void
    {
        // null means "don't pass to ssh2_connect" → libssh2 default negotiation.
        self::assertNull(SecurityProfile::Compatible->toMethodsArray());
    }

    public function testModernProfileLockedToEd25519Curve25519Chacha(): void
    {
        $m = SecurityProfile::Modern->toMethodsArray();

        self::assertNotNull($m);
        self::assertSame('ssh-ed25519', $m['hostkey']);
        self::assertStringContainsString('curve25519-sha256', $m['kex']);
        self::assertStringNotContainsString('sha1', strtolower($m['kex']));
        self::assertStringNotContainsString('sha1', strtolower($m['hostkey']));
        // No CBC modes — chacha20 + GCM only.
        self::assertStringContainsString('chacha20-poly1305', $m['client_to_server']['crypt']);
        self::assertStringNotContainsString('cbc', $m['client_to_server']['crypt']);
        self::assertStringNotContainsString('cbc', $m['server_to_client']['crypt']);
        // Encrypt-then-MAC over SHA-256/512 only.
        self::assertStringContainsString('etm', $m['client_to_server']['mac']);
        self::assertStringNotContainsString('sha1', strtolower($m['client_to_server']['mac']));
    }

    public function testLegacyProfileIncludesWeakAlgorithmsForOldServers(): void
    {
        $m = SecurityProfile::Legacy->toMethodsArray();

        self::assertNotNull($m);
        // Legacy is the bucket for "talks to a 2008 appliance" — it
        // explicitly admits SHA-1 MAC, CBC modes, and group14 KEX.
        self::assertStringContainsString('aes256-cbc', $m['client_to_server']['crypt']);
        self::assertStringContainsString('diffie-hellman-group14', $m['kex']);
        self::assertStringContainsString('hmac-sha1', $m['client_to_server']['mac']);
    }

    public function testConnectPassesMethodsArrayWhenProfileGiven(): void
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

        $capturedMethods = null;
        $ssh2->expects(self::once())
            ->method('connect')
            ->willReturnCallback(
                static function (string $host, int $port, ?array $methods = null) use ($session, &$capturedMethods): object {
                    $capturedMethods = $methods;

                    return $session;
                },
            );
        $ssh2->method('authPassword')->willReturn(true);
        $ssh2->method('sftp')->willReturn($sftp);

        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->connect('example.com', 22, securityProfile: SecurityProfile::Modern);

        self::assertNotNull($capturedMethods);
        self::assertSame('ssh-ed25519', $capturedMethods['hostkey']);
    }

    public function testConnectPassesNoMethodsArrayWhenCompatibleProfileGiven(): void
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

        $capturedMethods = 'not-called';
        $ssh2->expects(self::once())
            ->method('connect')
            ->willReturnCallback(
                static function (string $host, int $port, ?array $methods = null) use ($session, &$capturedMethods): object {
                    $capturedMethods = $methods;

                    return $session;
                },
            );
        $ssh2->method('authPassword')->willReturn(true);
        $ssh2->method('sftp')->willReturn($sftp);

        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->connect('example.com', 22, securityProfile: SecurityProfile::Compatible);

        self::assertNull($capturedMethods, 'Compatible profile must pass null to ssh2_connect');
    }

    public function testConnectLogsNoticeWhenLegacyProfileIsUsed(): void
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

        $logger = new CapturingLogger();
        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setLogger($logger);
        $client->connect('example.com', 22, securityProfile: SecurityProfile::Legacy);

        $notices = $logger->at('notice');
        $legacyNotices = array_filter(
            $notices,
            static fn(array $r): bool => str_contains($r['message'], 'SecurityProfile::Legacy'),
        );
        self::assertCount(1, $legacyNotices, 'Legacy profile should emit a notice-level warning');
    }
}
