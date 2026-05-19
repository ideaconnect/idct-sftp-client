<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Checksum;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Checksum\RedownloadRemoteHasher;
use IDCT\Networking\Ssh\Checksum\RemoteHasherInterface;
use IDCT\Networking\Ssh\Checksum\ShellSumRemoteHasher;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * P4 follow-up: opt-in checksum verification.
 *
 * Both ShellSumRemoteHasher and RedownloadRemoteHasher are tested
 * end-to-end through SftpClient's upload/download wrappers using the
 * FakeSftpStreamWrapper so we never depend on a real SSH server.
 */
#[CoversClass(ShellSumRemoteHasher::class)]
#[CoversClass(RedownloadRemoteHasher::class)]
#[CoversClass(SftpClient::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\RetryClassifier::class)]
#[UsesClass(\IDCT\Networking\Ssh\Auth\AuthDispatcher::class)]
#[UsesClass(\IDCT\Networking\Ssh\Transfer\StreamCopier::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(TransferException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class RemoteHasherTest extends TestCase
{
    private SftpFixture $fixture;
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

    // ─── ShellSumRemoteHasher (parsing) ─────────────────────────────

    public function testShellSumHasherAlgorithmAccessor(): void
    {
        $h = new ShellSumRemoteHasher('sha1', 'sha1sum');
        self::assertSame('sha1', $h->algorithm());
    }

    public function testShellSumHasherParsesStandardOutput(): void
    {
        // Simulate "deadbeef  /some/path" — the format every coreutils
        // sumcommand uses.
        $client = $this->newConnectedClient();
        $expectedDigest = str_repeat('a', 64);
        $this->ssh2->method('exec')->willReturnCallback(
            static function (mixed $session, string $cmd) use ($expectedDigest): mixed {
                $fakeOutput = $expectedDigest . '  /some/path';
                $stream = fopen('php://memory', 'r+b');
                if ($stream === false) {
                    return false;
                }
                fwrite($stream, $fakeOutput);
                rewind($stream);

                return $stream;
            },
        );

        $hasher = new ShellSumRemoteHasher();
        self::assertSame($expectedDigest, $hasher->hash($client, '/some/path'));
    }

    public function testShellSumHasherEscapesShellMetacharacters(): void
    {
        $captured = null;
        $client = $this->newConnectedClient();
        $this->ssh2->method('exec')->willReturnCallback(
            static function (mixed $session, string $cmd) use (&$captured): mixed {
                $captured = $cmd;
                $stream = fopen('php://memory', 'r+b');
                if ($stream === false) {
                    return false;
                }
                fwrite($stream, str_repeat('a', 64) . '  /x');
                rewind($stream);

                return $stream;
            },
        );

        $hasher = new ShellSumRemoteHasher();
        $hasher->hash($client, "/path with' tricky\" name");

        self::assertNotNull($captured);
        // escapeshellarg wraps in single quotes and escapes embedded ones.
        self::assertStringContainsString("'/path with'", $captured);
    }

    public function testShellSumHasherThrowsWhenExecReturnsFalse(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('exec')->willReturn(false);

        $hasher = new ShellSumRemoteHasher();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('ssh2_exec returned false');
        $hasher->hash($client, '/file');
    }

    public function testShellSumHasherThrowsOnEmptyOutput(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('exec')->willReturnCallback(
            static function (): mixed {
                $stream = fopen('php://memory', 'r+b');

                return $stream === false ? false : $stream;
            },
        );

        $hasher = new ShellSumRemoteHasher();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('empty output');
        $hasher->hash($client, '/file');
    }

    public function testShellSumHasherThrowsOnUnparseableOutput(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('exec')->willReturnCallback(
            static function (): mixed {
                $stream = fopen('php://memory', 'r+b');
                if ($stream === false) {
                    return false;
                }
                fwrite($stream, "not-a-digest no-spaces-either-but-no-hex-leader");
                rewind($stream);

                return $stream;
            },
        );

        $hasher = new ShellSumRemoteHasher();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('could not parse digest');
        $hasher->hash($client, '/file');
    }

    public function testShellSumHasherThrowsWhenNotConnected(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        // NOT connected — sshSession is null.

        $hasher = new ShellSumRemoteHasher();
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('SftpClient is not connected');
        $hasher->hash($client, '/file');
    }

    // ─── RedownloadRemoteHasher ────────────────────────────────────

    public function testRedownloadHasherAlgorithmAccessor(): void
    {
        self::assertSame('md5', (new RedownloadRemoteHasher('md5'))->algorithm());
    }

    public function testRedownloadHasherStreamsViaDownloadStreamAndHashes(): void
    {
        // Pre-stage a remote file; downloadStream will pull it via the
        // FakeSftpStreamWrapper.
        $payload = "the rain in spain falls mainly on the plain";
        $this->fixture->writeRemote('/source.txt', $payload);
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

            return file_exists($abs) ? stat($abs) : false;
        });
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $hasher = new RedownloadRemoteHasher('sha256');
        $expectedHex = hash('sha256', $payload);
        self::assertSame($expectedHex, $hasher->hash($client, '/source.txt'));
    }

    // ─── Wiring into SftpClient (upload/download verify) ───────────

    public function testUploadThrowsWhenRemoteHashDoesNotMatchLocal(): void
    {
        $local = $this->fixture->rootDir . '/up.txt';
        file_put_contents($local, 'hello');

        $client = $this->newConnectedClient(atomic: false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );
        $hasher = new class implements RemoteHasherInterface {
            public function algorithm(): string
            {
                return 'sha256';
            }

            public function hash(SftpClient $client, string $remotePath): string
            {
                return str_repeat('f', 64); // deliberately wrong
            }
        };
        $client->setRemoteHasher($hasher);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Checksum mismatch');
        $client->upload($local, '/dest.txt');
    }

    public function testUploadPassesWhenHashMatches(): void
    {
        $local = $this->fixture->rootDir . '/up.txt';
        $payload = 'hello-world';
        file_put_contents($local, $payload);
        $expected = hash('sha256', $payload);

        $client = $this->newConnectedClient(atomic: false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );
        $captured = null;
        $hasher = new class ($expected, $captured) implements RemoteHasherInterface {
            public function __construct(public string $expectedHash, public ?string $sawPath = null) {}

            public function algorithm(): string
            {
                return 'sha256';
            }

            public function hash(SftpClient $client, string $remotePath): string
            {
                $this->sawPath = $remotePath;

                return $this->expectedHash;
            }
        };
        self::assertSame($client, $client->setRemoteHasher($hasher));
        self::assertSame($hasher, $client->getRemoteHasher());

        $client->upload($local, '/dest.txt');
        self::assertSame('/dest.txt', $hasher->sawPath);
    }

    public function testDownloadThrowsWhenRemoteHashDoesNotMatchLocal(): void
    {
        $this->fixture->writeRemote('/source.txt', 'remote-bytes');
        $localDest = $this->fixture->rootDir . '/dl.txt';

        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

            return file_exists($abs) ? stat($abs) : false;
        });
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );
        $client->setRemoteHasher(new class implements RemoteHasherInterface {
            public function algorithm(): string
            {
                return 'sha256';
            }

            public function hash(SftpClient $client, string $remotePath): string
            {
                return str_repeat('0', 64);
            }
        });

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Checksum mismatch');
        $client->download('/source.txt', $localDest);
    }

    public function testVerifyHashThrowsWhenAlgorithmIsUnknown(): void
    {
        // Bogus algorithm → hash_file throws ValueError; verifyRemoteHash
        // translates it into a library TransferException.
        $client = $this->newConnectedClient(atomic: false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );
        $client->setRemoteHasher(new class implements RemoteHasherInterface {
            public function algorithm(): string
            {
                return 'nonexistent-algo-xyz';
            }

            public function hash(SftpClient $client, string $remotePath): string
            {
                return 'irrelevant';
            }
        });

        $local = $this->fixture->rootDir . '/exists.txt';
        file_put_contents($local, 'data');

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('hash algorithm "nonexistent-algo-xyz" is not supported');
        $client->upload($local, '/dest.txt');
    }

    public function testVerifyHashThrowsWhenLocalFileMissing(): void
    {
        // hash_file returns false when the file disappears between
        // upload completion and the verify call. Hard to trigger naturally
        // since upload requires the file to exist; force the race by
        // calling the helper directly via reflection.
        $client = $this->newConnectedClient(atomic: false);
        $client->setRemoteHasher(new class implements RemoteHasherInterface {
            public function algorithm(): string
            {
                return 'sha256';
            }

            public function hash(SftpClient $client, string $remotePath): string
            {
                return str_repeat('0', 64);
            }
        });

        $ref = new \ReflectionMethod($client, 'verifyRemoteHash');
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('could not hash local file');
        $ref->invoke($client, '/path/that/does/not/exist.bin', '/remote');
    }

    // ─── helpers ────────────────────────────────────────────────────

    private function newConnectedClient(bool $atomic = false): SftpClient
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy(), $atomic);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $client->connect('example.com');

        return $client;
    }
}
