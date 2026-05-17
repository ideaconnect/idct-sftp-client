<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper;
use IDCT\Networking\Ssh\Tests\Support\RecordingProgressListener;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * P6 — streaming & progress callback coverage.
 *
 * - Progress lifecycle: started → progress×N → completed (on success) OR
 *   started → progress×N → failed (on failure). Exactly one terminator
 *   per started.
 * - chunkSize affects the per-progress emission cadence; oversize / unset
 *   value are validated.
 * - uploadStream / downloadStream round-trip arbitrary PHP stream resources
 *   and honour the atomic upload flag.
 */
#[CoversClass(SftpClient::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\TransferException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\InvalidPathException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
final class StreamingAndProgressTest extends TestCase
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

    // ─── chunkSize accessors ───────────────────────────────────────────

    public function testChunkSizeDefaultsToOneMib(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertSame(SftpClient::DEFAULT_CHUNK_SIZE, $client->getChunkSize());
        self::assertSame(1 << 20, $client->getChunkSize());
    }

    public function testConstructorAcceptsCustomChunkSize(): void
    {
        $client = new SftpClient(false, $this->ssh2, null, true, 64 * 1024);
        self::assertSame(65_536, $client->getChunkSize());
    }

    public function testConstructorRejectsZeroChunkSize(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('chunkSize must be >= 1');
        new SftpClient(false, $this->ssh2, null, true, 0);
    }

    public function testSetChunkSizeFluent(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertSame($client, $client->setChunkSize(4096));
        self::assertSame(4096, $client->getChunkSize());
    }

    public function testSetChunkSizeRejectsNonPositive(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('chunkSize must be >= 1');
        $client->setChunkSize(0);
    }

    // ─── progress lifecycle ────────────────────────────────────────────

    public function testUploadEmitsStartedProgressCompleted(): void
    {
        // 5 bytes file, chunkSize=2 → expect started, progress(2), progress(4),
        // progress(5), completed(5).
        $local = $this->localFile('progress-up', 'hello');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient(atomic: false);
        $client->setChunkSize(2);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->upload($local, '/uploads/dest.bin', $listener);

        self::assertSame(
            ['started', 'progress', 'progress', 'progress', 'completed'],
            $listener->eventNames(),
        );
        self::assertSame([2, 4, 5], $listener->progressBytes());
        self::assertSame(['upload', 5], $listener->events[0]['args']);
        self::assertSame([5], $listener->events[4]['args']);
        self::assertSame('hello', $this->fixture->readRemote('/uploads/dest.bin'));
    }

    public function testUploadEmitsFailedWhenStreamCopyFails(): void
    {
        $local = $this->localFile('progress-fail', 'doomed');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient(atomic: false);

        $remoteUri = 'ssh2.sftp://1/uploads/poisoned';
        FakeSftpStreamWrapper::$writeFailures[$remoteUri] = true;
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        try {
            $client->upload($local, '/uploads/poisoned', $listener);
            self::fail('expected TransferException');
        } catch (TransferException) {
            // expected
        }

        // started + failed; the failed terminator carries the original throwable.
        self::assertSame('started', $listener->events[0]['event']);
        self::assertSame('failed', $listener->events[\count($listener->events) - 1]['event']);
        self::assertInstanceOf(
            TransferException::class,
            $listener->events[\count($listener->events) - 1]['args'][0],
        );
        // No completed must have fired.
        self::assertNotContains('completed', $listener->eventNames());
    }

    public function testAtomicUploadFailsBeforeCompletedWhenRenameFails(): void
    {
        // Verify the atomic-rename failure path also surfaces as failed(),
        // not completed() — important because the stream copy already
        // succeeded by the time the rename runs.
        $local = $this->localFile('rename-fail', 'data');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient(atomic: true);

        $this->ssh2->method('sftpRename')->willReturn(false);
        $this->ssh2->method('sftpUnlink')->willReturn(true);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        try {
            $client->upload($local, '/uploads/dest.bin', $listener);
            self::fail('expected TransferException');
        } catch (TransferException) {
            // expected
        }

        $names = $listener->eventNames();
        self::assertNotContains('completed', $names, 'rename failure must NOT signal completed');
        self::assertSame('failed', end($names));
    }

    public function testDownloadEmitsLifecycle(): void
    {
        $this->fixture->writeRemote('/remote/source.bin', 'xy');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient();
        $client->setChunkSize(1);

        $this->ssh2->method('sftpStat')->willReturn(['size' => 2]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->download('/remote/source.bin', $this->fixture->rootDir . '/dl.bin', $listener);

        self::assertSame(
            ['started', 'progress', 'progress', 'completed'],
            $listener->eventNames(),
        );
        self::assertSame(['download', 2], $listener->events[0]['args']);
        self::assertSame([2], $listener->events[3]['args']);
    }

    public function testResumeUploadEmitsLifecycleWithResumeOperationLabel(): void
    {
        $local = $this->localFile('resume-progress', 'AAAABBBB');
        $this->fixture->writeRemote('/uploads/.dest.bin.resume', 'AAAA');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient(atomic: true);
        $client->setChunkSize(2);

        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

            return is_file($abs) ? ['size' => filesize($abs)] : false;
        });
        $this->ssh2->method('sftpRename')->willReturnCallback(function (mixed $h, string $from, string $to): bool {
            return rename(
                $this->fixture->rootDir . '/' . ltrim($from, '/'),
                $this->fixture->rootDir . '/' . ltrim($to, '/'),
            );
        });
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeUpload($local, '/uploads/dest.bin', progress: $listener);

        self::assertSame('resumeUpload', $listener->events[0]['args'][0]);
        self::assertSame(['completed', 8], [end($listener->events)['event'], end($listener->events)['args'][0]]);
    }

    public function testResumeDownloadNoopStillEmitsStartedAndCompleted(): void
    {
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');
        file_put_contents($this->fixture->rootDir . '/local-done.bin', 'done');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);

        $client->resumeDownload('/source.bin', 'done.bin', progress: $listener);

        // No progress() fires (no bytes copied), but the lifecycle must be
        // complete so listeners can finalize their UI / spinner / etc.
        self::assertSame(['started', 'completed'], $listener->eventNames());
        self::assertSame(['resumeDownload', 4], $listener->events[0]['args']);
        self::assertSame([4], $listener->events[1]['args']);
    }

    // ─── uploadStream ─────────────────────────────────────────────────

    public function testUploadStreamRoundTripsFromMemoryStream(): void
    {
        $payload = 'streamed-payload';
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);
        fwrite($stream, $payload);
        rewind($stream);

        $client = $this->newConnectedClient(atomic: false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->uploadStream($stream, '/uploads/from-stream.bin');
        fclose($stream);

        self::assertSame($payload, $this->fixture->readRemote('/uploads/from-stream.bin'));
    }

    public function testUploadStreamHonoursAtomicFlag(): void
    {
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);
        fwrite($stream, 'atomic-stream');
        rewind($stream);

        $client = $this->newConnectedClient(atomic: true);
        $renamed = null;
        $this->ssh2->expects(self::once())
            ->method('sftpRename')
            ->willReturnCallback(function (mixed $h, string $from, string $to) use (&$renamed): bool {
                $renamed = [$from, $to];

                return rename(
                    $this->fixture->rootDir . '/' . ltrim($from, '/'),
                    $this->fixture->rootDir . '/' . ltrim($to, '/'),
                );
            });
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->uploadStream($stream, '/uploads/atomic.bin');
        fclose($stream);

        self::assertNotNull($renamed);
        self::assertMatchesRegularExpression(
            '#^/uploads/\.atomic\.bin\.partial-[0-9a-f]{8}$#',
            $renamed[0],
        );
        self::assertSame('/uploads/atomic.bin', $renamed[1]);
        self::assertSame('atomic-stream', $this->fixture->readRemote('/uploads/atomic.bin'));
    }

    public function testUploadStreamRejectsNonResource(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('must be an open resource');
        // @phpstan-ignore-next-line — deliberately passing a non-resource for validation test
        $client->uploadStream('not a resource', '/uploads/x.bin');
    }

    public function testUploadStreamRejectsNegativeExpectedSize(): void
    {
        $client = $this->newConnectedClient();
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);

        try {
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('expectedSize must be >= 0');
            $client->uploadStream($stream, '/uploads/x.bin', -1);
        } finally {
            fclose($stream);
        }
    }

    public function testUploadStreamThrowsOnSizeMismatch(): void
    {
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);
        fwrite($stream, 'only4');
        rewind($stream);

        $client = $this->newConnectedClient(atomic: false);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        try {
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Stream length mismatch');
            // Claim 10 bytes; the memory stream actually has 5.
            $client->uploadStream($stream, '/uploads/wrong.bin', 10);
        } finally {
            fclose($stream);
        }
    }

    public function testUploadStreamFailsWhenRemoteOpenFails(): void
    {
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);
        fwrite($stream, 'data');
        rewind($stream);

        $client = $this->newConnectedClient(atomic: false);
        $remoteUri = 'ssh2.sftp://1/uploads/blocked';
        FakeSftpStreamWrapper::$openFailures[$remoteUri] = true;
        $this->ssh2->method('sftpStreamUri')->willReturn($remoteUri);

        try {
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Unable to open remote file for writing');
            $client->uploadStream($stream, '/uploads/blocked');
        } finally {
            fclose($stream);
        }
    }

    public function testUploadStreamAtomicCleansUpPartialOnFailure(): void
    {
        $stream = fopen('php://memory', 'r+b');
        self::assertNotFalse($stream);
        fwrite($stream, 'doomed');
        rewind($stream);

        $client = $this->newConnectedClient(atomic: true);
        $this->ssh2->expects(self::once())->method('sftpUnlink')->willReturn(true);
        $this->ssh2->expects(self::never())->method('sftpRename');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$writeFailures[$uri] = true;

                return $uri;
            },
        );

        try {
            $this->expectException(TransferException::class);
            $client->uploadStream($stream, '/uploads/doomed.bin');
        } finally {
            fclose($stream);
        }
    }

    // ─── downloadStream ──────────────────────────────────────────────

    public function testDownloadStreamReturnsBytesWritten(): void
    {
        $this->fixture->writeRemote('/source.bin', 'twelve-bytes');
        $client = $this->newConnectedClient();
        $sink = fopen('php://memory', 'r+b');
        self::assertNotFalse($sink);

        $this->ssh2->method('sftpStat')->willReturn(['size' => 12]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $bytes = $client->downloadStream('/source.bin', $sink);
        self::assertSame(12, $bytes);
        rewind($sink);
        self::assertSame('twelve-bytes', stream_get_contents($sink));
        fclose($sink);
    }

    public function testDownloadStreamRejectsNonResource(): void
    {
        $client = $this->newConnectedClient();
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('must be an open resource');
        // @phpstan-ignore-next-line — deliberately passing a non-resource
        $client->downloadStream('/source.bin', 'not a resource');
    }

    public function testDownloadStreamMissingRemoteThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);
        $sink = fopen('php://memory', 'r+b');
        self::assertNotFalse($sink);

        try {
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Remote file does not exist');
            $client->downloadStream('/missing.bin', $sink);
        } finally {
            fclose($sink);
        }
    }

    public function testDownloadStreamFailsWhenRemoteOpenFails(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);
        $sink = fopen('php://memory', 'r+b');
        self::assertNotFalse($sink);

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$openFailures[$uri] = true;

                return $uri;
            },
        );

        try {
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Unable to open remote file');
            $client->downloadStream('/source.bin', $sink);
        } finally {
            fclose($sink);
        }
    }

    public function testDownloadStreamEmitsLifecycle(): void
    {
        $this->fixture->writeRemote('/source.bin', 'abc');
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient();
        $client->setChunkSize(1);
        $sink = fopen('php://memory', 'r+b');
        self::assertNotFalse($sink);

        $this->ssh2->method('sftpStat')->willReturn(['size' => 3]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->downloadStream('/source.bin', $sink, $listener);
        fclose($sink);

        self::assertSame(
            ['started', 'progress', 'progress', 'progress', 'completed'],
            $listener->eventNames(),
        );
        self::assertSame(['downloadStream', 3], $listener->events[0]['args']);
        self::assertSame([3], $listener->events[4]['args']);
    }

    // ─── chunkSize integration ─────────────────────────────────────────

    public function testLargerChunkSizeEmitsFewerProgressEvents(): void
    {
        $local = $this->localFile('chunked', str_repeat('x', 100));
        $listener = new RecordingProgressListener();
        $client = $this->newConnectedClient(atomic: false);
        $client->setChunkSize(50);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->upload($local, '/uploads/chunked.bin', $listener);

        // 100 bytes / 50-byte chunks = exactly 2 progress events.
        self::assertSame([50, 100], $listener->progressBytes());
    }

    // ─── helpers ───────────────────────────────────────────────────────

    private function localFile(string $name, string $contents): string
    {
        $path = $this->fixture->rootDir . '/local-' . bin2hex(random_bytes(4)) . '-' . $name . '.txt';
        file_put_contents($path, $contents);

        return $path;
    }

    private function newConnectedClient(bool $verifyFileSize = false, bool $atomic = false): SftpClient
    {
        $client = new SftpClient($verifyFileSize, $this->ssh2, new NoRetryPolicy(), $atomic);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $client->connect('example.com');

        return $client;
    }
}
