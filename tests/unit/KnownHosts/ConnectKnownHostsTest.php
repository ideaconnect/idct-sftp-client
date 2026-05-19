<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\KnownHosts;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\KnownHosts\HostKeyDecision;
use IDCT\Networking\Ssh\KnownHosts\KnownHostsFile;
use IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Covers the P8 plumbing in {@see SftpClient::connect()} that delegates
 * host-key verification to a {@see KnownHostsFile}. The KnownHostsFile
 * parser/appender is covered in detail by KnownHostsFileTest — this class
 * only verifies the decision routing (Trusted / Mismatch / NoEntries +
 * Reject vs TrustOnFirstUse).
 */
#[CoversClass(SftpClient::class)]
#[UsesClass(KnownHostsFile::class)]
#[UsesClass(HostKeyDecision::class)]
#[UsesClass(UnknownHostPolicy::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(FingerprintAlgorithm::class)]
#[UsesClass(FingerprintEncoding::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConnectionException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
final class ConnectKnownHostsTest extends TestCase
{
    private string $tmpDir;
    private object $session;
    private object $sftpHandle;

    /** @var Ssh2FunctionsInterface&MockObject */
    private Ssh2FunctionsInterface $ssh2;

    /** Lowercase-hex SHA-1, 40 chars — the format ssh2_fingerprint hands us. */
    private const SERVER_FP = 'abcdef0123456789abcdef0123456789abcdef01';

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/idct-connect-kh-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0o700, true);
        $this->session = new \stdClass();
        $this->sftpHandle = new class {
            public function __toString(): string
            {
                return '1';
            }
        };
        $this->ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->method('fingerprint')->willReturn(self::SERVER_FP);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmpDir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->tmpDir);
    }

    public function testTrustedHostConnectsSuccessfully(): void
    {
        $path = $this->tmpDir . '/known';
        file_put_contents($path, 'example.com sha1-fpr ' . self::SERVER_FP . "\n");

        $client = $this->newClient();
        // disconnect() fires on __destruct, so don't pin a "never" expectation
        // here — assert only that connect() completed without throwing.
        $this->ssh2->method('disconnect')->willReturn(true);

        $client->connect('example.com', 22, knownHostsFile: $path);
        self::assertNotNull($client->getCredentials());
    }

    public function testMismatchRejectsRegardlessOfPolicy(): void
    {
        $path = $this->tmpDir . '/mismatch';
        file_put_contents($path, 'example.com sha1-fpr ' . str_repeat('f', 40) . "\n");

        $client = $this->newClient();
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);

        // Mismatch is a MITM signal — TrustOnFirstUse must NOT override it.
        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Known-hosts mismatch for example.com:22');
        $client->connect(
            'example.com',
            22,
            knownHostsFile: $path,
            onUnknownHost: UnknownHostPolicy::TrustOnFirstUse,
        );
    }

    public function testUnknownHostUnderRejectPolicyRefusesConnection(): void
    {
        $path = $this->tmpDir . '/known';
        file_put_contents($path, 'other.example.com sha1-fpr ' . str_repeat('1', 40) . "\n");

        $client = $this->newClient();
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Unknown host example.com:22');
        $client->connect('example.com', 22, knownHostsFile: $path);
    }

    public function testUnknownHostUnderTofuAppendsAndProceeds(): void
    {
        $path = $this->tmpDir . '/empty';
        file_put_contents($path, '');

        $client = $this->newClient();
        // disconnect() fires on __destruct, so don't pin a "never" expectation
        // here — assert only that connect() completed without throwing.
        $this->ssh2->method('disconnect')->willReturn(true);

        $client->connect(
            'example.com',
            22,
            knownHostsFile: $path,
            onUnknownHost: UnknownHostPolicy::TrustOnFirstUse,
        );

        // The TOFU append wrote our fingerprint to the file.
        $body = file_get_contents($path);
        self::assertStringContainsString('example.com sha1-fpr ' . self::SERVER_FP, $body);

        // A second connect via a fresh client should now classify as Trusted
        // (no TOFU append since the entry already exists). disconnect() still
        // fires on the destructor — that's expected.
        $secondClient = $this->newClient();
        $secondClient->connect('example.com', 22, knownHostsFile: $path);

        // File still has exactly one entry for example.com — no duplicate
        // append on the second connect.
        $reloaded = file_get_contents($path);
        self::assertSame(1, substr_count($reloaded, 'example.com sha1-fpr ' . self::SERVER_FP));
    }

    public function testUnreadableFingerprintAbortsKnownHostsCheck(): void
    {
        $path = $this->tmpDir . '/known';
        file_put_contents($path, 'example.com sha1-fpr ' . self::SERVER_FP . "\n");

        $ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $ssh2->method('connect')->willReturn($this->session);
        $ssh2->method('fingerprint')->willReturn(false); // unreadable
        $ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);

        $client = new SftpClient(false, $ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Could not read host key fingerprint for example.com:22');
        $client->connect('example.com', 22, knownHostsFile: $path);
    }

    public function testKnownHostsAndExpectedFingerprintBothRunSuccessPath(): void
    {
        // Both checks must pass when both are configured.
        $path = $this->tmpDir . '/known';
        file_put_contents($path, 'example.com sha1-fpr ' . self::SERVER_FP . "\n");

        $client = $this->newClient();
        // disconnect() fires on __destruct, so don't pin a "never" expectation
        // here — assert only that connect() completed without throwing.
        $this->ssh2->method('disconnect')->willReturn(true);

        $client->connect(
            'example.com',
            22,
            expectedFingerprint: self::SERVER_FP,
            fingerprintAlgorithm: FingerprintAlgorithm::Sha256,
            fingerprintEncoding: FingerprintEncoding::Hex,
            knownHostsFile: $path,
        );
        self::assertNotNull($client->getCredentials());
    }

    private function newClient(): SftpClient
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        return $client;
    }
}
