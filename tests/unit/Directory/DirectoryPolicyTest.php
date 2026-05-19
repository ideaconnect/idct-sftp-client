<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Directory;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Directory\ConflictPolicy;
use IDCT\Networking\Ssh\Directory\DirectoryFailure;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\SymlinkPolicy;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * P3 follow-up — ConflictPolicy + SymlinkPolicy + best-effort wiring.
 *
 * Existing happy-path coverage lives in DirectoryOperationsTest; this
 * class adds the policy matrix.
 */
#[CoversClass(SftpClient::class)]
#[CoversClass(ConflictPolicy::class)]
#[CoversClass(SymlinkPolicy::class)]
#[CoversClass(DirectoryFailure::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(UploadResult::class)]
#[UsesClass(DownloadResult::class)]
#[UsesClass(\IDCT\Networking\Ssh\Directory\RemoteEntry::class)]
#[UsesClass(\IDCT\Networking\Ssh\Directory\EntryType::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\RemoteFilesystemException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\TransferException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\InvalidPathException::class)]
final class DirectoryPolicyTest extends TestCase
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

    // ─── ConflictPolicy on upload ────────────────────────────────────

    public function testUploadDirectorySkipsExistingRemoteFile(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/a.txt', 'aaa');
        file_put_contents($root . '/b.txt', 'bb');
        // Pre-existing remote file at /remote/a.txt — Skip should bypass it.
        $this->fixture->writeRemote('/remote/a.txt', 'OLD');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $result = $client->uploadDirectory(
            $root,
            '/remote',
            onConflict: ConflictPolicy::Skip,
        );

        self::assertSame(1, $result->filesTransferred, 'b.txt only; a.txt skipped');
        self::assertSame(2, $result->bytesTransferred);
        self::assertCount(1, $result->skipped);
        self::assertStringContainsString('a.txt', $result->skipped[0]);
        self::assertSame('OLD', $this->fixture->readRemote('/remote/a.txt'), 'existing file untouched');
        self::assertSame('bb', $this->fixture->readRemote('/remote/b.txt'));
    }

    public function testUploadDirectoryFailsOnExistingRemoteFile(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/a.txt', 'aaa');
        $this->fixture->writeRemote('/remote/a.txt', 'OLD');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('refusing to overwrite existing remote file');
        $client->uploadDirectory($root, '/remote', onConflict: ConflictPolicy::Fail);
    }

    public function testUploadDirectoryOverwriteRemainsDefault(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/a.txt', 'NEW');
        $this->fixture->writeRemote('/remote/a.txt', 'OLD');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $result = $client->uploadDirectory($root, '/remote'); // default policy

        self::assertSame(1, $result->filesTransferred);
        self::assertSame([], $result->skipped);
        self::assertSame('NEW', $this->fixture->readRemote('/remote/a.txt'));
    }

    // ─── SymlinkPolicy on upload ────────────────────────────────────

    public function testUploadDirectoryFollowsSymlinkToFile(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/target.txt', 'real-content');
        symlink($root . '/target.txt', $root . '/link.txt');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $result = $client->uploadDirectory(
            $root,
            '/remote',
            symlinks: SymlinkPolicy::Follow,
        );

        // Both files transferred (target + the symlink-resolved one).
        self::assertSame(2, $result->filesTransferred);
        self::assertSame('real-content', $this->fixture->readRemote('/remote/target.txt'));
        self::assertSame('real-content', $this->fixture->readRemote('/remote/link.txt'));
        self::assertSame([], $result->skipped);
    }

    public function testUploadDirectoryFollowsSymlinkToDirWithCycleDetection(): void
    {
        // src/
        //   inner/
        //     real.txt
        //   loop -> ../src         (cycle!)
        $root = $this->fixture->rootDir . '/src';
        mkdir($root . '/inner', 0o755, true);
        file_put_contents($root . '/inner/real.txt', 'real');
        symlink($root, $root . '/loop'); // loop back to self

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $result = $client->uploadDirectory(
            $root,
            '/remote',
            symlinks: SymlinkPolicy::Follow,
        );

        // Cycle was detected; real file still transferred exactly once.
        self::assertSame('real', $this->fixture->readRemote('/remote/inner/real.txt'));
        // The cycle entry is in skipped with a "(cycle)" marker.
        $cycleHits = array_filter(
            $result->skipped,
            static fn(string $p): bool => str_contains($p, '(cycle)'),
        );
        self::assertNotEmpty($cycleHits, 'expected the cycle entry to be recorded as skipped');
    }

    // ─── Best-effort on upload ──────────────────────────────────────

    public function testUploadDirectoryBestEffortCollectsFailures(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/a.txt', 'aaa');
        file_put_contents($root . '/b.txt', 'bb');
        $this->fixture->writeRemote('/remote/b.txt', 'EXISTS'); // will trigger Fail

        $client = $this->newConnectedClientWithFakeFs(atomic: false);

        $result = $client->uploadDirectory(
            $root,
            '/remote',
            onConflict: ConflictPolicy::Fail,
            bestEffort: true,
        );

        // a.txt uploaded; b.txt failed (Fail conflict) but recorded.
        self::assertSame(1, $result->filesTransferred);
        self::assertCount(1, $result->failures);
        self::assertInstanceOf(DirectoryFailure::class, $result->failures[0]);
        self::assertStringContainsString('b.txt', $result->failures[0]->path);
        self::assertSame(RemoteFilesystemException::class, $result->failures[0]->exceptionClass);
    }

    public function testUploadDirectoryBestEffortRecordsDirectoryFailureToo(): void
    {
        // Force the remote mkdir for /remote/sub to refuse, so the recursive
        // descent hits the directory-side catch branch (not the file branch).
        $root = $this->fixture->rootDir . '/src';
        mkdir($root . '/sub', 0o755, true);
        file_put_contents($root . '/top.txt', 'top');
        file_put_contents($root . '/sub/inner.txt', 'inner');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        // Override sftpMkdir to refuse only the nested path; everything
        // else (including the root mkdir) still works.
        $abs = fn(string $p): string => $this->fixture->rootDir . '/' . ltrim($p, '/');
        $this->ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );
        $this->ssh2->method('sftpStat')->willReturnCallback(
            static function (mixed $h, string $p) use ($abs): array|false {
                $real = $abs($p);
                if (! file_exists($real)) {
                    return false;
                }
                $stat = stat($real);

                return $stat === false ? false : $stat;
            },
        );
        $this->ssh2->method('sftpMkdir')->willReturnCallback(
            static function (mixed $h, string $p, int $mode, bool $recursive) use ($abs): bool {
                if (str_ends_with($p, '/remote/sub')) {
                    return false; // refuse this one mkdir
                }

                return @mkdir($abs($p), $mode, $recursive) || is_dir($abs($p));
            },
        );

        $freshClient = new SftpClient(false, $this->ssh2, new NoRetryPolicy(), false);
        $freshClient->setCredentials(Credentials::withPassword('alice', 'secret'));
        $freshClient->connect('example.com');

        $result = $freshClient->uploadDirectory(
            $root,
            '/remote',
            bestEffort: true,
        );

        // top.txt transferred; sub/* failed (directory-level failure recorded).
        self::assertSame(1, $result->filesTransferred);
        $subFailures = array_filter(
            $result->failures,
            static fn(DirectoryFailure $f): bool => str_contains($f->path, '/sub'),
        );
        self::assertNotEmpty($subFailures, 'expected a directory-level failure for /sub');
    }

    public function testDownloadDirectoryBestEffortRecordsDirectoryFailureToo(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }
        // Pre-create the local dest tree so the FIRST mkdir succeeds; then
        // make the dest read-only so the NESTED mkdir for /source/sub fails.
        $this->fixture->writeRemote('/source/top.txt', 'top');
        $this->fixture->writeRemote('/source/sub/inner.txt', 'inner');
        $localDest = $this->fixture->rootDir . '/dest';
        mkdir($localDest, 0o555);

        try {
            $client = $this->newConnectedClientWithFakeFs();
            $result = $client->downloadDirectory(
                '/source',
                $localDest,
                bestEffort: true,
            );

            // top.txt also can't be written (dir is read-only) → its file
            // failure is collected too; sub/ fails at the mkdir step (also
            // collected via the directory-level catch).
            $subFailures = array_filter(
                $result->failures,
                static fn(DirectoryFailure $f): bool => str_contains($f->path, '/source/sub'),
            );
            self::assertNotEmpty($subFailures, 'expected a directory-level failure for /source/sub');
        } finally {
            chmod($localDest, 0o755);
        }
    }

    public function testUploadDirectoryBestEffortStillRaisesUnderAbortMode(): void
    {
        // Sanity: with bestEffort=false (default), the same scenario propagates.
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/a.txt', 'aaa');
        $this->fixture->writeRemote('/remote/a.txt', 'EXISTS');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $this->expectException(RemoteFilesystemException::class);
        $client->uploadDirectory($root, '/remote', onConflict: ConflictPolicy::Fail);
    }

    // ─── ConflictPolicy on download ─────────────────────────────────

    public function testDownloadDirectorySkipsExistingLocalFile(): void
    {
        $this->fixture->writeRemote('/source/a.txt', 'remote-a');
        $this->fixture->writeRemote('/source/b.txt', 'remote-b');
        $localDest = $this->fixture->rootDir . '/dest';
        mkdir($localDest, 0o755, true);
        file_put_contents($localDest . '/a.txt', 'OLD');

        $client = $this->newConnectedClientWithFakeFs();
        $result = $client->downloadDirectory(
            '/source',
            $localDest,
            onConflict: ConflictPolicy::Skip,
        );

        self::assertSame(1, $result->filesTransferred);
        self::assertCount(1, $result->skipped);
        self::assertSame('OLD', file_get_contents($localDest . '/a.txt'), 'existing local file untouched');
        self::assertSame('remote-b', file_get_contents($localDest . '/b.txt'));
    }

    public function testDownloadDirectoryFailsOnExistingLocalFile(): void
    {
        $this->fixture->writeRemote('/source/a.txt', 'remote-a');
        $localDest = $this->fixture->rootDir . '/dest';
        mkdir($localDest, 0o755, true);
        file_put_contents($localDest . '/a.txt', 'OLD');

        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('refusing to overwrite existing local file');
        $client->downloadDirectory('/source', $localDest, onConflict: ConflictPolicy::Fail);
    }

    public function testDownloadDirectoryBestEffortCollectsFailures(): void
    {
        $this->fixture->writeRemote('/source/a.txt', 'a');
        $this->fixture->writeRemote('/source/b.txt', 'b');
        $localDest = $this->fixture->rootDir . '/dest';
        mkdir($localDest, 0o755, true);
        file_put_contents($localDest . '/a.txt', 'EXISTS');

        $client = $this->newConnectedClientWithFakeFs();
        $result = $client->downloadDirectory(
            '/source',
            $localDest,
            onConflict: ConflictPolicy::Fail,
            bestEffort: true,
        );

        self::assertSame(1, $result->filesTransferred);
        self::assertCount(1, $result->failures);
        self::assertSame(ConfigurationException::class, $result->failures[0]->exceptionClass);
    }

    public function testDownloadDirectoryLogsWhenSymlinkFollowRequestedButUnsupported(): void
    {
        // Remote symlink — Follow on the download side is a deferred
        // feature; the code path records a notice + adds to skipped.
        $this->fixture->writeRemote('/source/real.txt', 'real');
        symlink(
            $this->fixture->rootDir . '/source/real.txt',
            $this->fixture->rootDir . '/source/link.txt',
        );
        $localDest = $this->fixture->rootDir . '/dest';

        $client = $this->newConnectedClientWithFakeFs();
        $result = $client->downloadDirectory(
            '/source',
            $localDest,
            symlinks: SymlinkPolicy::Follow,
        );

        // Skipped contains the link.
        $linkSkipped = array_filter(
            $result->skipped,
            static fn(string $p): bool => str_contains($p, 'link.txt'),
        );
        self::assertNotEmpty($linkSkipped, 'remote symlink should still be in skipped list under Follow');
        // The real file transferred.
        self::assertSame('real', file_get_contents($localDest . '/real.txt'));
    }

    // ─── DirectoryFailure value object ──────────────────────────────

    public function testDirectoryFailureValueObjectRoundTrip(): void
    {
        $f = new DirectoryFailure('/some/path', 'reason text', \RuntimeException::class);
        self::assertSame('/some/path', $f->path);
        self::assertSame('reason text', $f->reason);
        self::assertSame(\RuntimeException::class, $f->exceptionClass);
    }

    // ─── helpers (copied wiring from DirectoryOperationsTest) ──────────

    private function newConnectedClientWithFakeFs(bool $atomic = false): SftpClient
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy(), $atomic);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(
            static fn(object $h, string $p): string => 'ssh2.sftp://1/' . ltrim($p, '/'),
        );

        $abs = fn(string $p): string => $this->fixture->rootDir . '/' . ltrim($p, '/');

        $this->ssh2->method('sftpMkdir')->willReturnCallback(
            static fn(mixed $h, string $p, int $mode, bool $recursive): bool =>
                @mkdir($abs($p), $mode, $recursive) || is_dir($abs($p)),
        );
        $this->ssh2->method('sftpRmdir')->willReturnCallback(
            static fn(mixed $h, string $p): bool => @rmdir($abs($p)),
        );
        $this->ssh2->method('sftpUnlink')->willReturnCallback(
            static fn(mixed $h, string $p): bool => @unlink($abs($p)),
        );
        $this->ssh2->method('sftpStat')->willReturnCallback(
            static function (mixed $h, string $p) use ($abs): array|false {
                $real = $abs($p);
                if (! file_exists($real)) {
                    return false;
                }
                $stat = stat($real);

                return $stat === false ? false : $stat;
            },
        );

        $client->connect('example.com');

        return $client;
    }
}
