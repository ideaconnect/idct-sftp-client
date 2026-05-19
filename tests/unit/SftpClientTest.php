<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

#[CoversClass(SftpClient::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(FingerprintAlgorithm::class)]
#[UsesClass(FingerprintEncoding::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\AuthenticationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConnectionException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\RemoteFilesystemException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\TransferException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\InvalidPathException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
final class SftpClientTest extends TestCase
{
    private ?SftpFixture $fixture = null;

    private object $session;
    private object $sftpHandle;

    /** @var Ssh2FunctionsInterface&MockObject */
    private Ssh2FunctionsInterface $ssh2;

    protected function setUp(): void
    {
        $this->fixture = new SftpFixture();
        $this->session = new \stdClass();
        $this->sftpHandle = new class {
            public function __toString(): string
            {
                return '1';
            }
        };
        $this->ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
    }

    protected function tearDown(): void
    {
        $this->fixture = null;
    }

    // ─── construction / accessors ──────────────────────────────────────

    public function testFluentSettersReturnSelf(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertSame($client, $client->setLocalPrefix('/local/'));
        self::assertSame($client, $client->setRemotePrefix('/remote/'));
        self::assertSame($client, $client->enableFileSizeVerification());
        self::assertSame($client, $client->disableFileSizeVerification());
        self::assertSame('/local/', $client->getLocalPrefix());
        self::assertSame('/remote/', $client->getRemotePrefix());
    }

    public function testCredentialsRoundtrip(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertNull($client->getCredentials());
        $creds = Credentials::withNone('guest');
        self::assertSame($client, $client->setCredentials($creds));
        self::assertSame($creds, $client->getCredentials());
    }

    public function testConstructorAcceptsFileSizeVerificationFlag(): void
    {
        $client = new SftpClient(true, $this->ssh2);
        // Hit disable path so the flag flip is observable later.
        $client->disableFileSizeVerification();
        self::assertNotNull($client);
    }

    public function testSetLoggerIsHonoured(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $client->setLogger(new NullLogger());
        // No observable behaviour, but exercises the LoggerAwareTrait branch.
        self::assertNotNull($client);
    }

    // ─── connect() ─────────────────────────────────────────────────────

    public function testConnectRejectsMissingCredentials(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Credentials must be set before calling connect()');
        $client->connect('example.com');
    }

    public function testConnectFailsWhenSsh2ConnectReturnsFalse(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn(false);

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Could not connect to example.com:22.');
        $client->connect('example.com');
    }

    public function testConnectFailsWhenSftpSubsystemReturnsFalse(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn(false);
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Could not initialise SFTP subsystem.');
        $client->connect('example.com');
    }

    public function testConnectSucceedsAndStoresHandles(): void
    {
        $client = $this->newConnectedClient();
        // smoke: stat call should not blow up after connect
        $this->ssh2->method('sftpStat')->willReturn(['size' => 0]);
        self::assertSame(['size' => 0], $client->stat('/x'));
    }

    public function testConnectVerifiesFingerprintMatch(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->expects(self::once())->method('fingerprint')
            ->with($this->session, FingerprintAlgorithm::Sha256->value | FingerprintEncoding::Hex->value)
            ->willReturn('AABBCC');

        $client->connect('example.com', 22, null, 'aabbcc');
        self::assertSame($client, $client);
    }

    public function testConnectFingerprintReadFailureDisconnectsAndThrows(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('fingerprint')->willReturn(false);
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);
        $this->ssh2->expects(self::never())->method('authPassword');

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Could not read host key fingerprint');
        $client->connect('example.com', 22, null, 'aabb');
    }

    public function testConnectFingerprintMismatchDisconnectsAndThrows(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('fingerprint')->willReturn('AABBCC');
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);
        $this->ssh2->expects(self::never())->method('authPassword');

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Host key fingerprint mismatch');
        $client->connect('example.com', 22, null, 'DEADBEEF');
    }

    public function testConnectPropagatesAuthFailure(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(false);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('SSH authentication failed for user "alice" using Password mode.');
        $client->connect('example.com');
    }

    public function testConnectDispatchesPublicKeyAuth(): void
    {
        $pub = $this->tempKey('pub');
        $priv = $this->tempKey('priv');

        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withPublicKey('bob', $pub, $priv, 'phrase'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->expects(self::once())
            ->method('authPublicKey')
            ->with($this->session, 'bob', $pub, $priv, 'phrase')
            ->willReturn(true);

        $client->connect('example.com');
    }

    public function testConnectDispatchesNoneAuth(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withNone('guest'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->expects(self::once())
            ->method('authNone')
            ->with($this->session, 'guest')
            ->willReturn(true);

        $client->connect('example.com');
    }

    public function testConnectDispatchesBothAuthRequiringBothLegs(): void
    {
        $pub = $this->tempKey('pub');
        $priv = $this->tempKey('priv');

        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withBoth('carol', 'pw', $pub, $priv));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->expects(self::once())->method('authPublicKey')->willReturn(true);
        $this->ssh2->expects(self::once())->method('authPassword')->willReturn(true);

        $client->connect('example.com');
    }

    public function testConnectBothAuthFailsWhenPubkeyFails(): void
    {
        $pub = $this->tempKey('pub');
        $priv = $this->tempKey('priv');

        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withBoth('carol', 'pw', $pub, $priv));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPublicKey')->willReturn(false);
        $this->ssh2->method('authPassword')->willReturn(true);

        $this->expectException(AuthenticationException::class);
        $client->connect('example.com');
    }

    public function testConnectBothAuthFailsWhenPasswordFails(): void
    {
        $pub = $this->tempKey('pub');
        $priv = $this->tempKey('priv');

        $client = new SftpClient(false, $this->ssh2);
        $client->setCredentials(Credentials::withBoth('carol', 'pw', $pub, $priv));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPublicKey')->willReturn(true);
        $this->ssh2->method('authPassword')->willReturn(false);

        $this->expectException(AuthenticationException::class);
        $client->connect('example.com');
    }

    public function testConnectWithCustomAlgorithmAndEncoding(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->expects(self::once())->method('fingerprint')
            ->with($this->session, FingerprintAlgorithm::Md5->value | FingerprintEncoding::Raw->value)
            ->willReturn('xx');

        $client->connect('h', 22, null, 'XX', FingerprintAlgorithm::Md5, FingerprintEncoding::Raw);
        self::assertNotNull($client);
    }

    public function testConnectTimeoutProbeFailsFast(): void
    {
        $client = $this->newClientWithCredentials();
        $this->ssh2->expects(self::never())->method('connect');
        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('TCP probe to 127.0.0.1:1 failed within 1s');
        // Port 1 is reserved and not listening.
        $client->connect('127.0.0.1', 1, 1);
    }

    public function testConnectTimeoutProbeSucceedsThenProceeds(): void
    {
        // Open a real listening socket so probeTcp succeeds.
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($server, $errstr);
        $port = (int) parse_url(stream_socket_get_name($server, false), PHP_URL_PORT);

        try {
            $client = $this->newClientWithCredentials();
            $this->ssh2->method('connect')->willReturn($this->session);
            $this->ssh2->method('authPassword')->willReturn(true);
            $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
            $client->connect('127.0.0.1', $port, 1);
            self::assertNotNull($client);
        } finally {
            fclose($server);
        }
    }

    // ─── close() / __destruct ──────────────────────────────────────────

    public function testCloseIsIdempotentBeforeConnect(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $this->ssh2->expects(self::never())->method('disconnect');
        self::assertSame($client, $client->close());
    }

    public function testCloseDisconnectsAndClearsHandles(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);
        $client->close();
        // calling again is a no-op
        $client->close();
    }

    public function testCloseSwallowsDisconnectExceptions(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('disconnect')->willThrowException(new \RuntimeException('peer already gone'));
        $client->close();
        self::assertTrue(true);
    }

    public function testDestructorClosesSession(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('disconnect')->with($this->session)->willReturn(true);
        unset($client);
    }

    // ─── download() ────────────────────────────────────────────────────

    public function testDownloadRequiresOpenSftp(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $this->expectException(ConnectionException::class);
        $client->download('/x');
    }

    public function testDownloadMissingRemoteFileThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Remote file does not exist');
        $client->download('/missing');
    }

    public function testDownloadCopiesAndUsesBasenameWhenNoLocalGiven(): void
    {
        $this->fixture->writeRemote('/remote/big.bin', 'hello world');
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/out/');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 11]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        mkdir($this->fixture->rootDir . '/out', 0o755, true);
        $client->download('/remote/big.bin');

        self::assertSame('hello world', file_get_contents($this->fixture->rootDir . '/out/big.bin'));
    }

    public function testDownloadUsesExplicitLocalName(): void
    {
        $this->fixture->writeRemote('/remote/file.bin', 'payload');
        $client = $this->newConnectedClient();
        $local = $this->fixture->rootDir . '/explicit.bin';

        $this->ssh2->method('sftpStat')->willReturn(['size' => 7]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $client->download('/remote/file.bin', $local);
        self::assertSame('payload', file_get_contents($local));
    }

    public function testDownloadFailsWhenRemoteOpenFails(): void
    {
        $client = $this->newConnectedClient();
        $remoteUri = 'ssh2.sftp://1/remote/no-perms';
        FakeSftpStreamWrapper::$openFailures[$remoteUri] = true;

        $this->ssh2->method('sftpStat')->willReturn(['size' => 5]);
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Unable to open remote file');
        $client->download('/remote/no-perms');
    }

    public function testDownloadFailsWhenLocalOpenFails(): void
    {
        $this->fixture->writeRemote('/remote/ok', 'data');
        $client = $this->newConnectedClient();

        $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        // Local target points to a non-writable directory.
        $badLocal = '/proc/idct-target/cannot-write';

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Unable to open local file for writing');
        $client->download('/remote/ok', $badLocal);
    }

    public function testDownloadStreamCopyFailureThrows(): void
    {
        $this->fixture->writeRemote('/remote/r', 'data');
        $client = $this->newConnectedClient();
        $local = $this->fixture->rootDir . '/dl-r';

        $remoteUri = 'ssh2.sftp://1/remote/r';
        FakeSftpStreamWrapper::$readFailures[$remoteUri] = true;

        $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Failed to copy remote stream to local file');
        $client->download('/remote/r', $local);
    }

    public function testUploadStreamCopyFailureThrows(): void
    {
        $local = $this->localFile('uploadcopyfail', 'will not be delivered');
        $client = $this->newConnectedClient();

        $remoteUri = 'ssh2.sftp://1/blocked-writes';
        FakeSftpStreamWrapper::$writeFailures[$remoteUri] = true;
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Failed to copy local stream to remote file');
        $client->upload($local, '/blocked-writes');
    }

    public function testDownloadFileSizeVerificationMismatchThrows(): void
    {
        $this->fixture->writeRemote('/remote/r', 'abc');
        $client = $this->newConnectedClient(verifyFileSize: true);
        $local = $this->fixture->rootDir . '/local-r';

        $this->ssh2->method('sftpStat')->willReturn(['size' => 999]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after download');
        $client->download('/remote/r', $local);
    }

    public function testDownloadFileSizeVerificationSuccess(): void
    {
        $this->fixture->writeRemote('/remote/r', 'abcd');
        $client = $this->newConnectedClient(verifyFileSize: true);
        $local = $this->fixture->rootDir . '/ok-r';

        $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $client->download('/remote/r', $local);
        self::assertSame('abcd', file_get_contents($local));
    }

    // ─── upload() ──────────────────────────────────────────────────────

    public function testUploadMissingLocalFileThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Local file does not exist');
        $client->upload('/no/such/file');
    }

    public function testUploadUsesBasenameWhenNoRemoteNameGiven(): void
    {
        $local = $this->fixture->rootDir . '/source.txt';
        file_put_contents($local, 'up');
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/remote/');

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $client->upload($local);
        self::assertSame('up', $this->fixture->readRemote('/remote/source.txt'));
    }

    public function testUploadFailsWhenLocalOpenFails(): void
    {
        $local = '/dev/null/cant-read';
        $client = $this->newConnectedClient();
        // is_file() blocks before fopen, so this hits the "Local file does not exist" path.
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Local file does not exist');
        $client->upload($local);
    }

    public function testUploadFailsWhenLocalFopenFailsDespiteIsFile(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a file unreadable to root.');
        }

        $local = $this->localFile('unreadable', 'data');
        chmod($local, 0o000);

        try {
            $client = $this->newConnectedClient();
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Unable to open local file for reading');
            $client->upload($local, '/blocked');
        } finally {
            chmod($local, 0o644);
        }
    }

    public function testUploadFailsWhenRemoteOpenFails(): void
    {
        $local = $this->fixture->rootDir . '/src.txt';
        file_put_contents($local, 'x');
        $client = $this->newConnectedClient();

        $remoteUri = 'ssh2.sftp://1/blocked';
        FakeSftpStreamWrapper::$openFailures[$remoteUri] = true;
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Unable to open remote file for writing');
        $client->upload($local, 'blocked');
    }

    public function testUploadFileSizeVerificationSuccess(): void
    {
        $local = $this->localFile('v', 'hello');
        $client = $this->newConnectedClient(verifyFileSize: true);

        $this->ssh2->method('sftpStat')->willReturn(['size' => 5]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $client->upload($local, '/uploaded/v.txt');
        self::assertSame('hello', $this->fixture->readRemote('/uploaded/v.txt'));
    }

    public function testUploadFileSizeVerificationMismatchThrows(): void
    {
        $local = $this->localFile('v', 'hello');
        $client = $this->newConnectedClient(verifyFileSize: true);

        // Remote stat returns wrong size.
        $this->ssh2->method('sftpStat')->willReturn(['size' => 1]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after upload');
        $client->upload($local, '/uploaded/v.txt');
    }

    public function testUploadFileSizeVerificationMismatchWhenRemoteStatMissing(): void
    {
        $local = $this->localFile('v', 'hello');
        $client = $this->newConnectedClient(verifyFileSize: true);

        $this->ssh2->method('sftpStat')->willReturn(false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p) => 'ssh2.sftp://1/' . ltrim($p, '/')
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after upload');
        $client->upload($local, '/uploaded/v.txt');
    }

    // ─── scpDownload / scpUpload ──────────────────────────────────────

    public function testScpDownloadRequiresOpenSession(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $this->expectException(ConnectionException::class);
        $client->scpDownload('/x');
    }

    public function testScpUploadRequiresOpenSession(): void
    {
        $local = $this->localFile('s', 'x');
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $this->expectException(ConnectionException::class);
        $client->scpUpload($local);
    }

    public function testScpDownloadMissingFile(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);
        $this->expectException(TransferException::class);
        $client->scpDownload('/nope');
    }

    public function testScpDownloadFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 1]);
        $this->ssh2->method('scpRecv')->willReturn(false);
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Could not SCP-download');
        $client->scpDownload('/x');
    }

    public function testScpDownloadSuccessWithBasename(): void
    {
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/');
        $this->ssh2->method('sftpStat')->willReturn(['size' => 1]);
        $this->ssh2->expects(self::once())->method('scpRecv')
            ->with($this->session, '/r/file.bin', $this->fixture->rootDir . '/file.bin')
            ->willReturn(true);

        $client->scpDownload('/r/file.bin');
    }

    public function testScpDownloadSuccessWithExplicitName(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 1]);
        $this->ssh2->expects(self::once())->method('scpRecv')
            ->with($this->session, '/r/file.bin', '/tmp/x.bin')
            ->willReturn(true);
        $client->scpDownload('/r/file.bin', '/tmp/x.bin');
    }

    public function testScpUploadMissingLocal(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Local file does not exist');
        $client->scpUpload('/no/such');
    }

    public function testScpUploadFailureThrows(): void
    {
        $local = $this->fixture->rootDir . '/s.txt';
        file_put_contents($local, 'x');
        $client = $this->newConnectedClient();
        $this->ssh2->method('scpSend')->willReturn(false);
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Could not SCP-upload');
        $client->scpUpload($local);
    }

    public function testScpUploadSuccessWithBasename(): void
    {
        $local = $this->fixture->rootDir . '/s.txt';
        file_put_contents($local, 'x');
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/dest/');
        $this->ssh2->expects(self::once())->method('scpSend')
            ->with($this->session, $local, '/dest/s.txt', 0o644)
            ->willReturn(true);
        $client->scpUpload($local);
    }

    public function testScpUploadSuccessWithExplicitName(): void
    {
        $local = $this->fixture->rootDir . '/s.txt';
        file_put_contents($local, 'x');
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('scpSend')
            ->with($this->session, $local, '/explicit/path', 0o644)
            ->willReturn(true);
        $client->scpUpload($local, '/explicit/path');
    }

    // ─── remove / rename ───────────────────────────────────────────────

    public function testRemoveMissingFileThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->remove('/x');
    }

    public function testRemoveUnlinkFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 0]);
        $this->ssh2->method('sftpUnlink')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('Unable to remove remote file');
        $client->remove('/x');
    }

    public function testRemoveSuccessAppliesRemotePrefix(): void
    {
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/r/');
        $this->ssh2->expects(self::once())->method('sftpStat')->with($this->sftpHandle, '/r/file')->willReturn(['size' => 0]);
        $this->ssh2->expects(self::once())->method('sftpUnlink')->with($this->sftpHandle, '/r/file')->willReturn(true);
        $client->remove('file');
    }

    public function testRenameMissingSourceThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->rename('/a', '/b');
    }

    public function testRenameFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 0]);
        $this->ssh2->method('sftpRename')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->rename('/a', '/b');
    }

    public function testRenameAppliesRemotePrefixToBothSides(): void
    {
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/r/');
        $this->ssh2->method('sftpStat')->willReturn(['size' => 0]);
        $this->ssh2->expects(self::once())->method('sftpRename')
            ->with($this->sftpHandle, '/r/a', '/r/b')
            ->willReturn(true);
        $client->rename('a', 'b');
    }

    // ─── getFileList / stat / fileExists / makeDirectory / removeDirectory ────

    public function testGetFileListMissingDirectoryThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/missing');
        // url_stat on the fixture returns false because the dir doesn't exist.
        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('Remote directory does not exist');
        $client->getFileList('/missing');
    }

    public function testGetFileListOpenFailureThrows(): void
    {
        $this->fixture->writeRemote('/dir/a', '');
        $client = $this->newConnectedClient();
        $uri = 'ssh2.sftp://1/dir';
        $this->ssh2->method('sftpStreamUri')->willReturn($uri);
        // Stat succeeds (the dir exists) but opendir is forced to fail.
        FakeSftpStreamWrapper::$openFailures[$uri] = true;

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('Unable to open remote directory');
        $client->getFileList('/dir');
    }

    public function testGetFileListReturnsEntriesAndFiltersDots(): void
    {
        $this->fixture->writeRemote('/dir/a.txt', '');
        $this->fixture->writeRemote('/dir/b.txt', '');
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/dir');

        $entries = $client->getFileList('/dir');
        sort($entries);
        self::assertSame(['a.txt', 'b.txt'], $entries);
    }

    public function testGetFileListIncludesDotEntriesWhenAsked(): void
    {
        $this->fixture->writeRemote('/dir/a', '');
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/dir');

        $entries = $client->getFileList('/dir', includeDotEntries: true);
        self::assertContains('.', $entries);
        self::assertContains('..', $entries);
    }

    public function testStatFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->stat('/missing');
    }

    public function testStatSuccessReturnsArray(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 42]);
        self::assertSame(['size' => 42], $client->stat('/p'));
    }

    public function testMakeDirectoryFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpMkdir')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->makeDirectory('/p');
    }

    public function testMakeDirectorySuccessPassesDefaults(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('sftpMkdir')
            ->with($this->sftpHandle, '/p', 0o755, false)
            ->willReturn(true);
        $client->makeDirectory('/p');
    }

    public function testMakeDirectoryRecursivePassesFlag(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('sftpMkdir')
            ->with($this->sftpHandle, '/p/sub', 0o700, true)
            ->willReturn(true);
        $client->makeDirectory('/p/sub', 0o700, true);
    }

    public function testRemoveDirectoryFailureThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpRmdir')->willReturn(false);
        $this->expectException(RemoteFilesystemException::class);
        $client->removeDirectory('/p');
    }

    public function testRemoveDirectorySuccess(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->expects(self::once())->method('sftpRmdir')->with($this->sftpHandle, '/p')->willReturn(true);
        $client->removeDirectory('/p');
    }

    public function testFileExistsReturnsTrueForRealFile(): void
    {
        $this->fixture->writeRemote('/f', 'x');
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/f');
        self::assertTrue($client->fileExists('/f'));
    }

    public function testFileExistsReturnsFalseForMissingFile(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/nope');
        self::assertFalse($client->fileExists('/nope'));
    }

    // ─── path validation (P2 wiring) ───────────────────────────────────
    //
    // PathValidator has its own exhaustive tests; this block only verifies
    // SftpClient invokes it BEFORE touching the SFTP layer (so a malicious
    // path is rejected even on a non-connected client) and that the
    // joinRemote-based absolute-bypass holds for prefix-aware methods.

    public function testDownloadRejectsTraversalPath(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $this->ssh2->expects(self::never())->method('sftpStat');
        $this->expectException(InvalidPathException::class);
        $client->download('/data/../etc/passwd');
    }

    public function testUploadRejectsTraversalRemoteName(): void
    {
        $local = $this->localFile('safe', 'data');
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/safe/');
        $this->ssh2->expects(self::never())->method('sftpStreamUri');
        $this->expectException(InvalidPathException::class);
        $client->upload($local, '../etc/passwd');
    }

    public function testRenameRejectsNullByteInDestination(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('null byte');
        $client->rename('/a', "/b\0c");
    }

    public function testGetFileListRejectsCrlf(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('CR or LF');
        $client->getFileList("/dir\nlist");
    }

    public function testMakeDirectoryRejectsControlChar(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('control character');
        $client->makeDirectory("/dir\x07bad");
    }

    public function testUploadAbsolutePathBypassesPrefix(): void
    {
        // T6: absolute path opts out of prefix concatenation.
        $local = $this->localFile('s', 'data');
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/uploads/');

        // Expect sftpStreamUri called with the ABSOLUTE path, not /uploads/abs.
        $this->ssh2->expects(self::once())
            ->method('sftpStreamUri')
            ->with($this->sftpHandle, '/abs/dest.bin')
            ->willReturn('ssh2.sftp://1/abs/dest.bin');

        $client->upload($local, '/abs/dest.bin');
    }

    public function testRemoveAbsolutePathBypassesPrefix(): void
    {
        $client = $this->newConnectedClient();
        $client->setRemotePrefix('/uploads/');

        $this->ssh2->expects(self::once())
            ->method('sftpStat')
            ->with($this->sftpHandle, '/abs/path')
            ->willReturn(['size' => 0]);
        $this->ssh2->expects(self::once())
            ->method('sftpUnlink')
            ->with($this->sftpHandle, '/abs/path')
            ->willReturn(true);

        $client->remove('/abs/path');
    }

    // ─── helpers ────────────────────────────────────────────────────────

    private function localFile(string $name, string $contents): string
    {
        $path = sys_get_temp_dir() . '/idct-sftp-local-' . bin2hex(random_bytes(4)) . '-' . $name . '.txt';
        file_put_contents($path, $contents);

        return $path;
    }

    private function tempKey(string $label): string
    {
        $path = sys_get_temp_dir() . '/idct-sftp-key-' . bin2hex(random_bytes(4)) . '-' . $label;
        file_put_contents($path, "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n");

        return $path;
    }

    private function newClientWithCredentials(): SftpClient
    {
        // Default tests use NoRetryPolicy so single-attempt assertions hold;
        // retry-specific scenarios construct their own client with the
        // ExponentialBackoffRetryPolicy explicitly.
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        return $client;
    }

    private function newConnectedClient(bool $verifyFileSize = false, bool $atomicUploads = false): SftpClient
    {
        // Default atomicUploads=false here so the pre-P4 upload tests in this
        // class continue to assert against the final remote path without
        // needing every test to mock sftpRename. Atomic-flow tests below
        // construct their own client with atomicUploads=true.
        $client = new SftpClient($verifyFileSize, $this->ssh2, new NoRetryPolicy(), $atomicUploads);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);

        $client->connect('example.com');

        return $client;
    }
}
