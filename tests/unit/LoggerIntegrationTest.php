<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\CapturingLogger;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Verifies P7 wiring: SftpClient emits the expected log records at the
 * expected levels with the expected base context (correlation_id, host,
 * port). Not an exhaustive log-surface lock-in — message wording can change
 * without breaking these tests; what matters is that the records exist and
 * carry the right structured fields.
 */
#[CoversClass(SftpClient::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\RetryClassifier::class)]
#[CoversClass(\IDCT\Networking\Ssh\Auth\AuthDispatcher::class)]
#[UsesClass(\IDCT\Networking\Ssh\Transfer\StreamCopier::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\AuthenticationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
final class LoggerIntegrationTest extends TestCase
{
    private SftpFixture $fixture;
    private CapturingLogger $logger;
    private object $session;
    private object $sftpHandle;
    private Ssh2FunctionsInterface $ssh2;

    protected function setUp(): void
    {
        $this->fixture = new SftpFixture();
        $this->logger = new CapturingLogger();
        $this->session = new \stdClass();
        $this->sftpHandle = new class {
            public function __toString(): string
            {
                return '1';
            }
        };
        $this->ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
    }

    public function testConnectEmitsAttemptAndSuccessRecords(): void
    {
        $client = $this->connectedClient();

        $infos = $this->logger->at('info');
        self::assertCount(3, $infos, 'expect connect-attempt, auth-ok, connect-ok');
        self::assertSame('SSH connect attempt', $infos[0]['message']);
        self::assertSame('SSH authentication ok', $infos[1]['message']);
        self::assertSame('SSH connect ok', $infos[2]['message']);
    }

    public function testEveryRecordCarriesCorrelationAndHostPort(): void
    {
        $this->connectedClient();

        self::assertNotEmpty($this->logger->records);
        foreach ($this->logger->records as $r) {
            self::assertArrayHasKey('correlation_id', $r['context'], 'level=' . $r['level']);
            self::assertArrayHasKey('host', $r['context']);
            self::assertArrayHasKey('port', $r['context']);
            self::assertSame('example.com', $r['context']['host']);
            self::assertSame(22, $r['context']['port']);
            self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', (string) $r['context']['correlation_id']);
        }
    }

    public function testCorrelationIdIsStableWithinOneConnectAndResetsAcrossConnects(): void
    {
        $clientA = $this->connectedClient();
        $idA = $this->logger->records[0]['context']['correlation_id'];
        foreach ($this->logger->records as $r) {
            self::assertSame($idA, $r['context']['correlation_id']);
        }

        // Open a second connection on a fresh client; correlation_id must differ.
        $loggerB = new CapturingLogger();
        $clientB = new SftpClient(false, $this->ssh2);
        $clientB->setCredentials(Credentials::withPassword('alice', 'secret'));
        $clientB->setLogger($loggerB);
        $clientB->connect('example.com');
        $idB = $loggerB->records[0]['context']['correlation_id'];

        self::assertNotSame($idA, $idB);
    }

    public function testUserContextIsMergedIntoEveryRecord(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setLogger($this->logger);
        $client->setLogContext(['request_id' => 'req-abc', 'tenant' => 'acme']);
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);

        $client->connect('example.com');

        foreach ($this->logger->records as $r) {
            self::assertSame('req-abc', $r['context']['request_id']);
            self::assertSame('acme', $r['context']['tenant']);
        }
    }

    public function testSetLogContextStripsReservedKeys(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setLogger($this->logger);
        // Caller tries to inject conflicting values — client must overwrite them.
        $client->setLogContext([
            'correlation_id' => 'attacker-controlled',
            'host' => 'evil.example.com',
            'port' => 999,
            'safe_key' => 'kept',
        ]);
        // getLogContext mirrors what was stored after the reserved-key strip.
        self::assertSame(['safe_key' => 'kept'], $client->getLogContext());
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);

        $client->connect('example.com');

        $r = $this->logger->records[0];
        self::assertNotSame('attacker-controlled', $r['context']['correlation_id']);
        self::assertSame('example.com', $r['context']['host']);
        self::assertSame(22, $r['context']['port']);
        self::assertSame('kept', $r['context']['safe_key']);
    }

    public function testAuthFailureEmitsNoticeRecord(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setLogger($this->logger);
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(false);

        try {
            $client->connect('example.com');
            self::fail('expected AuthenticationException');
        } catch (AuthenticationException) {
            // expected
        }

        $notices = $this->logger->at('notice');
        self::assertCount(1, $notices);
        self::assertSame('SSH authentication rejected', $notices[0]['message']);
        self::assertSame('alice', $notices[0]['context']['user']);
        self::assertSame('Password', $notices[0]['context']['mode']);
        // critical: ensure no password leaked into the context
        self::assertArrayNotHasKey('password', $notices[0]['context']);
    }

    public function testCloseEmitsDebugAndClearsCorrelationId(): void
    {
        $client = $this->connectedClient();
        $this->ssh2->method('disconnect')->willReturn(true);
        $client->close();

        $debugs = $this->logger->at('debug');
        self::assertNotEmpty($debugs);
        $disconnect = array_values(array_filter(
            $debugs,
            static fn(array $r): bool => $r['message'] === 'SSH disconnect',
        ));
        self::assertCount(1, $disconnect);

        // After close(), there is no active connection scope — verify by calling
        // setLogContext + setLogger and confirming that a no-op log via close()
        // again doesn't append more records.
        $countBefore = \count($this->logger->records);
        $client->close();
        self::assertCount($countBefore, $this->logger->records);
    }

    public function testCloseSwallowingDisconnectExceptionLogsWarning(): void
    {
        $client = $this->connectedClient();
        $this->ssh2->method('disconnect')->willThrowException(new \RuntimeException('peer gone'));
        $client->close();

        $warnings = $this->logger->at('warning');
        self::assertCount(1, $warnings);
        self::assertSame(\RuntimeException::class, $warnings[0]['context']['exception']);
        self::assertSame('peer gone', $warnings[0]['context']['reason']);
    }

    public function testDownloadEmitsStartAndEndRecordsWithBytesAndDuration(): void
    {
        $this->fixture->writeRemote('/r/file.bin', 'payload-12');
        $client = $this->connectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 10]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $local = $this->fixture->rootDir . '/dl.bin';
        $client->download('/r/file.bin', $local);

        $debugs = array_values(array_filter(
            $this->logger->at('debug'),
            static fn(array $r): bool => $r['message'] === 'SFTP download start',
        ));
        self::assertCount(1, $debugs);
        self::assertSame('/r/file.bin', $debugs[0]['context']['remote']);
        self::assertSame(10, $debugs[0]['context']['size']);

        $infos = array_values(array_filter(
            $this->logger->at('info'),
            static fn(array $r): bool => $r['message'] === 'SFTP download ok',
        ));
        self::assertCount(1, $infos);
        self::assertSame(10, $infos[0]['context']['bytes']);
        self::assertGreaterThanOrEqual(0, $infos[0]['context']['duration_ms']);
    }

    public function testUploadEmitsStartAndEndRecords(): void
    {
        $local = $this->fixture->rootDir . '/src.txt';
        file_put_contents($local, 'hello');
        $client = $this->connectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $client->upload($local, '/dest.txt');

        self::assertTrue($this->logger->hasMessageContaining('SFTP upload start'));
        self::assertTrue($this->logger->hasMessageContaining('SFTP upload ok'));
    }

    public function testNullLoggerIsTheDefaultAndDoesNotBlowUp(): void
    {
        // No setLogger call: the constructor installs NullLogger; every log
        // call is a no-op. This is a smoke test ensuring log() funnels through
        // the null-safe operator and never crashes.
        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->method('disconnect')->willReturn(true);
        $client->connect('example.com');
        $client->close();
        self::assertTrue(true); // no exception == pass
    }

    private function connectedClient(): SftpClient
    {
        // atomicUploads=false: these tests assert on log records around the
        // upload flow itself; atomic semantics (partial+rename) get their
        // own coverage in AtomicUploadAndResumeTest.
        $client = new SftpClient(false, $this->ssh2, null, false);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $client->setLogger($this->logger);
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $client->connect('example.com');

        return $client;
    }
}
