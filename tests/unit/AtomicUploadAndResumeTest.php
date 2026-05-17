<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Verifies P4 — atomic upload pattern + resume semantics.
 *
 * Each test wires `sftpRename` / `sftpUnlink` to perform real ops inside
 * the SftpFixture tmpdir so post-rename / post-unlink assertions can read
 * the fake filesystem directly via `$fixture->readRemote()` /
 * `$fixture->remoteExists()`.
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
final class AtomicUploadAndResumeTest extends TestCase
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

    // ─── flag accessors ────────────────────────────────────────────────

    public function testAtomicUploadsDefaultsToTrue(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertTrue($client->getAtomicUploads());
    }

    public function testConstructorAcceptsAtomicFlag(): void
    {
        $client = new SftpClient(false, $this->ssh2, null, false);
        self::assertFalse($client->getAtomicUploads());
    }

    public function testEnableDisableToggle(): void
    {
        $client = new SftpClient(false, $this->ssh2, null, true);
        self::assertSame($client, $client->disableAtomicUploads());
        self::assertFalse($client->getAtomicUploads());
        self::assertSame($client, $client->enableAtomicUploads());
        self::assertTrue($client->getAtomicUploads());
    }

    // ─── atomic upload happy path ──────────────────────────────────────

    public function testAtomicUploadWritesToPartialThenRenames(): void
    {
        $local = $this->localFile('atomic', 'payload-data');
        $client = $this->newConnectedClient(atomic: true);

        $partialPathCaptured = null;
        $finalPathCaptured = null;
        $this->wireRename($partialPathCaptured, $finalPathCaptured);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->upload($local, '/uploads/dest.bin');

        self::assertNotNull($partialPathCaptured, 'sftpRename should have been invoked');
        self::assertNotNull($finalPathCaptured);
        self::assertSame('/uploads/dest.bin', $finalPathCaptured);
        // Partial sits next to the final under a `.{base}.partial-{uuid}` name.
        self::assertMatchesRegularExpression(
            '#^/uploads/\.dest\.bin\.partial-[0-9a-f]{8}$#',
            $partialPathCaptured,
        );
        // After the rename, the final path contains the payload and the
        // partial is gone from the fake filesystem.
        self::assertSame('payload-data', $this->fixture->readRemote('/uploads/dest.bin'));
        self::assertFalse($this->fixture->remoteExists($partialPathCaptured));
    }

    public function testAtomicUploadDisabledWritesDirectlyToFinalPath(): void
    {
        $local = $this->localFile('direct', 'no-rename');
        $client = $this->newConnectedClient(atomic: false);
        $client->setRemotePrefix('/uploads/');

        // sftpRename must NOT be called when atomic is off.
        $this->ssh2->expects(self::never())->method('sftpRename');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->upload($local, 'direct.bin');

        self::assertSame('no-rename', $this->fixture->readRemote('/uploads/direct.bin'));
    }

    // ─── atomic upload failure modes ───────────────────────────────────

    public function testAtomicUploadCleansUpPartialWhenStreamCopyFails(): void
    {
        $local = $this->localFile('fail', 'partial-bytes');
        $client = $this->newConnectedClient(atomic: true);

        $unlinked = [];
        $this->ssh2->expects(self::once())
            ->method('sftpUnlink')
            ->willReturnCallback(function (mixed $h, string $p) use (&$unlinked): bool {
                $unlinked[] = $p;
                $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

                return is_file($abs) ? @unlink($abs) : true;
            });
        $this->ssh2->expects(self::never())->method('sftpRename');

        // Poison every stream URI the wrapper hands out so stream_write
        // returns 0 → stream_copy_to_stream fails. Need a callback (not a
        // fixed URI) because the partial path includes a random uuid.
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$writeFailures[$uri] = true;

                return $uri;
            },
        );

        try {
            $client->upload($local, '/uploads/blocked');
            self::fail('expected TransferException');
        } catch (TransferException $e) {
            self::assertStringContainsString('Failed to copy local stream', $e->getMessage());
        }

        // Unlink fires with the partial path the client picked (random uuid).
        self::assertCount(1, $unlinked);
        self::assertMatchesRegularExpression(
            '#^/uploads/\.blocked\.partial-[0-9a-f]{8}$#',
            $unlinked[0],
        );
    }

    public function testAtomicUploadCleansUpPartialWhenRenameFails(): void
    {
        $local = $this->localFile('rename-fail', 'data');
        $client = $this->newConnectedClient(atomic: true);

        $renamed = false;
        $this->ssh2->method('sftpRename')->willReturnCallback(function () use (&$renamed): bool {
            $renamed = true;

            return false; // simulate server-side rename refusal
        });
        $this->ssh2->expects(self::once())->method('sftpUnlink')->willReturn(true);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        try {
            $client->upload($local, '/uploads/dest.bin');
            self::fail('expected TransferException');
        } catch (TransferException $e) {
            self::assertStringContainsString('rename of partial', $e->getMessage());
        }
        self::assertTrue($renamed, 'rename should have been attempted');
    }

    public function testAtomicUploadPartialCleanupSwallowsUnlinkException(): void
    {
        // If cleanup itself fails, we MUST propagate the ORIGINAL upload
        // failure, not the cleanup failure — otherwise debugging gets
        // misdirected.
        $local = $this->localFile('cleanup-throws', 'doomed');
        $client = $this->newConnectedClient(atomic: true);

        $this->ssh2->method('sftpUnlink')->willThrowException(new \RuntimeException('peer gone'));
        $this->ssh2->expects(self::never())->method('sftpRename');

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$writeFailures[$uri] = true;

                return $uri;
            },
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Failed to copy local stream');
        $client->upload($local, '/uploads/doomed');
    }

    public function testAtomicUploadFileSizeMismatchTriggersUnlink(): void
    {
        $local = $this->localFile('verify', 'hello');
        $client = $this->newConnectedClient(verifyFileSize: true, atomic: true);

        // Stat returns wrong size → mismatch → unlink the partial → throw.
        $this->ssh2->method('sftpStat')->willReturn(['size' => 1]);
        $this->ssh2->expects(self::once())->method('sftpUnlink')->willReturn(true);
        $this->ssh2->expects(self::never())->method('sftpRename');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after upload');
        $client->upload($local, '/uploads/verify.bin');
    }

    // ─── resumeUpload — happy path / offset auto-detection ─────────────

    public function testResumeUploadAutoDetectsOffsetFromExistingPartial(): void
    {
        // Local has 12 bytes, partial already holds the first 5.
        $local = $this->localFile('resume-up', 'hello-WORLD!');
        $this->fixture->writeRemote('/uploads/.dest.bin.resume', 'hello');

        $client = $this->newConnectedClient(atomic: true);
        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');
            if (! is_file($abs)) {
                return false;
            }

            return ['size' => filesize($abs)];
        });
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

        $client->resumeUpload($local, '/uploads/dest.bin');

        self::assertNotNull($renamed);
        self::assertSame('/uploads/.dest.bin.resume', $renamed[0]);
        self::assertSame('/uploads/dest.bin', $renamed[1]);
        self::assertSame('hello-WORLD!', $this->fixture->readRemote('/uploads/dest.bin'));
        self::assertFalse($this->fixture->remoteExists('/uploads/.dest.bin.resume'));
    }

    public function testResumeUploadWithExplicitOffsetSkipsStat(): void
    {
        $local = $this->localFile('explicit', 'AAAABBBB');
        $this->fixture->writeRemote('/uploads/.dest.bin.resume', 'AAAA');

        $client = $this->newConnectedClient(atomic: true);
        // sftpStat must NOT be called when caller supplies explicit offset.
        $this->ssh2->expects(self::never())->method('sftpStat');
        $this->ssh2->expects(self::once())->method('sftpRename')->willReturnCallback(
            function (mixed $h, string $from, string $to): bool {
                return rename(
                    $this->fixture->rootDir . '/' . ltrim($from, '/'),
                    $this->fixture->rootDir . '/' . ltrim($to, '/'),
                );
            },
        );
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeUpload($local, '/uploads/dest.bin', offset: 4);

        self::assertSame('AAAABBBB', $this->fixture->readRemote('/uploads/dest.bin'));
    }

    public function testResumeUploadStartsFromZeroWhenNoPartialExists(): void
    {
        $local = $this->localFile('fresh-resume', 'all-new');
        $client = $this->newConnectedClient(atomic: true);

        $this->ssh2->method('sftpStat')->willReturn(false); // no partial
        $this->ssh2->expects(self::once())->method('sftpRename')->willReturnCallback(
            function (mixed $h, string $from, string $to): bool {
                return rename(
                    $this->fixture->rootDir . '/' . ltrim($from, '/'),
                    $this->fixture->rootDir . '/' . ltrim($to, '/'),
                );
            },
        );
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeUpload($local, '/uploads/dest.bin');

        self::assertSame('all-new', $this->fixture->readRemote('/uploads/dest.bin'));
    }

    // ─── resumeUpload — argument validation ────────────────────────────

    public function testResumeUploadRejectsNegativeOffset(): void
    {
        $local = $this->localFile('bad', 'x');
        $client = $this->newConnectedClient(atomic: true);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Resume offset must be >= 0');
        $client->resumeUpload($local, '/uploads/d.bin', offset: -1);
    }

    public function testResumeUploadRejectsOffsetBeyondLocalFile(): void
    {
        $local = $this->localFile('short', 'tiny');
        $client = $this->newConnectedClient(atomic: true);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('exceeds local file size');
        $client->resumeUpload($local, '/uploads/d.bin', offset: 9999);
    }

    public function testResumeUploadMissingLocalThrows(): void
    {
        $client = $this->newConnectedClient(atomic: true);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Local file does not exist');
        $client->resumeUpload('/no/such/file', '/uploads/d.bin');
    }

    public function testResumeUploadRejectsInvalidRemotePath(): void
    {
        $local = $this->localFile('bad-remote', 'x');
        $client = $this->newConnectedClient(atomic: true);

        $this->expectException(InvalidPathException::class);
        $client->resumeUpload($local, '../etc/passwd');
    }

    // ─── resumeUpload — failure preserves partial ──────────────────────

    public function testResumeUploadDoesNotUnlinkPartialOnFailure(): void
    {
        // resumeUpload's whole job is preserving the partial across retries.
        // Unlike atomic upload, a failed resume must leave the partial intact.
        $local = $this->localFile('preserve', 'longer-data-here');
        $this->fixture->writeRemote('/uploads/.dest.bin.resume', 'lon');
        $client = $this->newConnectedClient(atomic: true);

        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

            return is_file($abs) ? ['size' => filesize($abs)] : false;
        });
        // sftpUnlink MUST NOT be called on resume failure.
        $this->ssh2->expects(self::never())->method('sftpUnlink');
        $this->ssh2->expects(self::never())->method('sftpRename');

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$writeFailures[$uri] = true;

                return $uri;
            },
        );

        try {
            $client->resumeUpload($local, '/uploads/dest.bin');
            self::fail('expected TransferException');
        } catch (TransferException) {
            // expected
        }

        // The partial still exists with its original prefix.
        self::assertTrue($this->fixture->remoteExists('/uploads/.dest.bin.resume'));
    }

    public function testResumeUploadRenameFailurePreservesPartial(): void
    {
        $local = $this->localFile('rename-pres', 'data-here');
        $this->fixture->writeRemote('/uploads/.dest.bin.resume', 'data');
        $client = $this->newConnectedClient(atomic: true);

        $this->ssh2->method('sftpStat')->willReturnCallback(function (mixed $h, string $p): array|false {
            $abs = $this->fixture->rootDir . '/' . ltrim($p, '/');

            return is_file($abs) ? ['size' => filesize($abs)] : false;
        });
        $this->ssh2->method('sftpRename')->willReturn(false);
        $this->ssh2->expects(self::never())->method('sftpUnlink');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        try {
            $client->resumeUpload($local, '/uploads/dest.bin');
            self::fail('expected TransferException');
        } catch (TransferException $e) {
            self::assertStringContainsString('rename of partial', $e->getMessage());
        }
        self::assertTrue($this->fixture->remoteExists('/uploads/.dest.bin.resume'));
    }

    public function testResumeUploadSizeMismatchAfterAppendThrows(): void
    {
        $local = $this->localFile('verify-resume', 'twelve-bytes');
        $client = $this->newConnectedClient(verifyFileSize: true, atomic: true);

        // For the auto-offset stat AND the post-upload size verification,
        // pretend the partial has the wrong final size.
        $this->ssh2->method('sftpStat')->willReturn(['size' => 999]);
        $this->ssh2->expects(self::never())->method('sftpRename');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('exceeds local file size');
        $client->resumeUpload($local, '/uploads/d.bin');
    }

    public function testResumeUploadFailsWhenLocalFopenFails(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a file unreadable to root.');
        }

        $local = $this->localFile('unreadable', 'data');
        chmod($local, 0o000);

        try {
            $client = $this->newConnectedClient(atomic: true);
            $this->ssh2->method('sftpStat')->willReturn(false);
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Unable to open local file for reading');
            $client->resumeUpload($local, '/uploads/dest.bin');
        } finally {
            chmod($local, 0o644);
        }
    }

    public function testSeekOrThrowRaisesWhenStreamRejectsSeek(): void
    {
        // The fseek-guard branch in doResumeUpload / doResumeDownload only
        // fires for pathological stream wrappers (regular-file streams seek
        // fine for any offset, even past EOF). Exercise the helper directly
        // via reflection with a known non-seekable stream (php://stdin in
        // CLI mode rejects fseek).
        $method = new \ReflectionMethod(SftpClient::class, 'seekOrThrow');

        // Bidirectional pipe — fseek returns -1.
        $pipes = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        self::assertNotFalse($pipes);
        [$reader, $writer] = $pipes;

        try {
            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Could not seek remote stream to offset 10: /some/path');
            $method->invoke(null, $reader, 10, 'remote stream', '/some/path');
        } finally {
            fclose($reader);
            fclose($writer);
        }
    }

    public function testResumeUploadFailsWhenPartialFopenFails(): void
    {
        $local = $this->localFile('partial-blocked', 'data');
        $client = $this->newConnectedClient(atomic: true);
        $this->ssh2->method('sftpStat')->willReturn(false);

        // Predict the partial URI by hand and poison it.
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$openFailures[$uri] = true;

                return $uri;
            },
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Unable to open remote file for writing');
        $client->resumeUpload($local, '/uploads/dest.bin');
    }

    public function testResumeUploadFailsWhenStreamCopyFails(): void
    {
        $local = $this->localFile('copy-fail', 'data');
        $client = $this->newConnectedClient(atomic: true);
        $this->ssh2->method('sftpStat')->willReturn(false);

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$writeFailures[$uri] = true;

                return $uri;
            },
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Failed to copy local stream');
        $client->resumeUpload($local, '/uploads/dest.bin');
    }

    public function testResumeUploadPartialSizeVerificationMismatch(): void
    {
        // Local file is 5 bytes. Auto-offset stat says partial is 0 bytes
        // (first call) so the client appends from byte 0. After the append,
        // the second stat for size verification returns the wrong size →
        // triggers the partial-size-mismatch branch.
        $local = $this->localFile('verify-mismatch', 'hello');
        $client = $this->newConnectedClient(verifyFileSize: true, atomic: true);

        $statCalls = 0;
        $this->ssh2->method('sftpStat')->willReturnCallback(function () use (&$statCalls): array|false {
            $statCalls++;

            // 1st call: auto-detect offset (no partial yet) → 0.
            // 2nd call: post-upload size verification → lie about size.
            return $statCalls === 1 ? false : ['size' => 999];
        });
        $this->ssh2->expects(self::never())->method('sftpRename');
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after resume upload');
        $client->resumeUpload($local, '/uploads/dest.bin');
    }

    public function testResumeUploadPartialPathForBasenameOnly(): void
    {
        // Exercises partialPath()'s `dir === '.'` branch — when the remote
        // is just a filename with no directory, the partial lives in cwd
        // with the dotfile prefix only.
        $local = $this->localFile('basename', 'plain');
        $client = $this->newConnectedClient(atomic: true);
        $this->ssh2->method('sftpStat')->willReturn(false);

        $renamePair = null;
        $this->ssh2->expects(self::once())
            ->method('sftpRename')
            ->willReturnCallback(function (mixed $h, string $from, string $to) use (&$renamePair): bool {
                $renamePair = [$from, $to];

                return rename(
                    $this->fixture->rootDir . '/' . ltrim($from, '/'),
                    $this->fixture->rootDir . '/' . ltrim($to, '/'),
                );
            });
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeUpload($local, 'dest.bin');

        self::assertNotNull($renamePair);
        self::assertSame('.dest.bin.resume', $renamePair[0]);
        self::assertSame('dest.bin', $renamePair[1]);
    }

    // ─── resumeDownload ────────────────────────────────────────────────

    public function testResumeDownloadAutoDetectsOffsetFromExistingLocal(): void
    {
        $this->fixture->writeRemote('/source.bin', 'AAAABBBBCCCC');

        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');
        // Pre-stage a partial local file of 8 bytes — resume should pick up at 8.
        file_put_contents($this->fixture->rootDir . '/local-dest.bin', 'AAAABBBB');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 12]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeDownload('/source.bin', 'dest.bin');

        self::assertSame('AAAABBBBCCCC', file_get_contents($this->fixture->rootDir . '/local-dest.bin'));
    }

    public function testResumeDownloadStartsFreshWhenLocalAbsent(): void
    {
        $this->fixture->writeRemote('/source.bin', 'whole');
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 5]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $client->resumeDownload('/source.bin', 'fresh.bin');

        self::assertSame('whole', file_get_contents($this->fixture->rootDir . '/local-fresh.bin'));
    }

    public function testResumeDownloadIsNoopWhenLocalAlreadyMatchesRemoteSize(): void
    {
        // If the local file size already equals the remote, resume must not
        // re-open the remote stream. Asserting on sftpStreamUri being never
        // called is the cleanest indicator.
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');
        file_put_contents($this->fixture->rootDir . '/local-done.bin', 'finished');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 8]);
        $this->ssh2->expects(self::never())->method('sftpStreamUri');

        $client->resumeDownload('/source.bin', 'done.bin');

        self::assertSame('finished', file_get_contents($this->fixture->rootDir . '/local-done.bin'));
    }

    public function testResumeDownloadRejectsNegativeOffset(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 10]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('Resume offset must be >= 0');
        $client->resumeDownload('/source.bin', 'd.bin', offset: -1);
    }

    public function testResumeDownloadRejectsOffsetBeyondRemoteSize(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(['size' => 10]);

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('exceeds remote file size');
        $client->resumeDownload('/source.bin', 'd.bin', offset: 9999);
    }

    public function testResumeDownloadMissingRemoteThrows(): void
    {
        $client = $this->newConnectedClient();
        $this->ssh2->method('sftpStat')->willReturn(false);

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Remote file does not exist');
        $client->resumeDownload('/source.bin', 'd.bin');
    }

    public function testResumeDownloadRejectsInvalidRemotePath(): void
    {
        $client = $this->newConnectedClient();

        $this->expectException(InvalidPathException::class);
        $client->resumeDownload('../etc/passwd', 'd.bin');
    }

    public function testResumeDownloadFailsWhenRemoteOpenFails(): void
    {
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');
        $this->ssh2->method('sftpStat')->willReturn(['size' => 10]);

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$openFailures[$uri] = true;

                return $uri;
            },
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Unable to open remote file');
        $client->resumeDownload('/source.bin', 'blocked.bin');
    }

    public function testResumeDownloadFailsWhenStreamCopyFails(): void
    {
        $this->fixture->writeRemote('/source.bin', 'plenty-of-bytes');
        $client = $this->newConnectedClient();
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');
        $this->ssh2->method('sftpStat')->willReturn(['size' => 15]);

        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static function (object $h, string $p): string {
                $uri = 'ssh2.sftp://1/' . ltrim($p, '/');
                FakeSftpStreamWrapper::$readFailures[$uri] = true;

                return $uri;
            },
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Failed to copy remote stream');
        $client->resumeDownload('/source.bin', 'copyfail.bin');
    }

    public function testResumeDownloadFailsWhenLocalOpenFails(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }

        $this->fixture->writeRemote('/source.bin', 'data');
        $client = $this->newConnectedClient();
        // Point the local prefix at a path under an unwritable dir.
        $unwritable = $this->fixture->rootDir . '/ro';
        mkdir($unwritable, 0o555);

        try {
            $client->setLocalPrefix($unwritable . '/');
            $this->ssh2->method('sftpStat')->willReturn(['size' => 4]);
            $this->ssh2->method('sftpStreamUri')->willReturnCallback(
                static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
            );

            $this->expectException(TransferException::class);
            $this->expectExceptionMessage('Unable to open local file for writing');
            $client->resumeDownload('/source.bin', 'blocked.bin');
        } finally {
            chmod($unwritable, 0o755);
        }
    }

    public function testResumeDownloadSizeVerificationMismatchThrows(): void
    {
        // Remote stat says size=10. The fake stream wrapper happily reads
        // whatever bytes the file has on disk. Pre-stage a 4-byte source
        // so the appended local file ends up smaller than the announced
        // size and verification trips.
        $this->fixture->writeRemote('/source.bin', 'tiny');
        $client = $this->newConnectedClient(verifyFileSize: true);
        $client->setLocalPrefix($this->fixture->rootDir . '/local-');

        $this->ssh2->method('sftpStat')->willReturn(['size' => 10]);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('File size mismatch after resume download');
        $client->resumeDownload('/source.bin', 'mismatched.bin');
    }

    // ─── helpers ───────────────────────────────────────────────────────

    /**
     * @param-out string|null $partialOut
     * @param-out string|null $finalOut
     */
    private function wireRename(?string &$partialOut, ?string &$finalOut): void
    {
        $this->ssh2->expects(self::once())
            ->method('sftpRename')
            ->willReturnCallback(function (mixed $h, string $from, string $to) use (&$partialOut, &$finalOut): bool {
                $partialOut = $from;
                $finalOut = $to;
                $fromAbs = $this->fixture->rootDir . '/' . ltrim($from, '/');
                $toAbs = $this->fixture->rootDir . '/' . ltrim($to, '/');
                $dir = \dirname($toAbs);
                if (! is_dir($dir)) {
                    mkdir($dir, 0o755, true);
                }

                return is_file($fromAbs) && rename($fromAbs, $toAbs);
            });
    }

    private function localFile(string $name, string $contents): string
    {
        $path = $this->fixture->rootDir . '/local-' . bin2hex(random_bytes(4)) . '-' . $name . '.txt';
        file_put_contents($path, $contents);

        return $path;
    }

    private function newConnectedClient(bool $verifyFileSize = false, bool $atomic = true): SftpClient
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
