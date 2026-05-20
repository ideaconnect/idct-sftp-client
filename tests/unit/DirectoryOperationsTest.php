<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\EntryType;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
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
 * P3 — recursive directory operations.
 *
 * Tests wire the Ssh2FunctionsInterface mock so that sftpMkdir / sftpRmdir
 * / sftpUnlink / sftpStat / sftpStreamUri operate on the SftpFixture
 * tmpdir. This lets walk/uploadDirectory/downloadDirectory/removeDirectoryTree
 * exercise real filesystem semantics (recursion, symlinks, ordering) without
 * needing an SSH server.
 */
#[CoversClass(SftpClient::class)]
#[UsesClass(\IDCT\Networking\Ssh\Auth\AuthDispatcher::class)]
#[UsesClass(\IDCT\Networking\Ssh\Transfer\StreamCopier::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConnectionException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\InvalidPathException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\RemoteFilesystemException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\TransferException::class)]
#[UsesClass(RemoteEntry::class)]
#[UsesClass(EntryType::class)]
#[UsesClass(UploadResult::class)]
#[UsesClass(DownloadResult::class)]
#[UsesClass(\IDCT\Networking\Ssh\Directory\SymlinkPolicy::class)]
final class DirectoryOperationsTest extends TestCase
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

    // ─── walk() ───────────────────────────────────────────────────────

    public function testWalkYieldsPostOrder(): void
    {
        // Tree:
        //   /tree/a.txt
        //   /tree/sub/b.txt
        //   /tree/sub/nested/c.txt
        $this->fixture->writeRemote('/tree/a.txt', 'A');
        $this->fixture->writeRemote('/tree/sub/b.txt', 'B');
        $this->fixture->writeRemote('/tree/sub/nested/c.txt', 'C');

        $client = $this->newConnectedClientWithFakeFs();

        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array($client->walk('/tree'), false);

        // Build path → position index so we can assert ordering invariants
        // without depending on readdir's enumeration order.
        $position = [];
        foreach ($entries as $i => $e) {
            $position[$e->path] = $i;
        }

        // All five expected entries are present with the right types.
        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        self::assertCount(5, $entries);
        self::assertSame(EntryType::File, $byPath['/tree/a.txt']->type);
        self::assertSame(EntryType::File, $byPath['/tree/sub/b.txt']->type);
        self::assertSame(EntryType::File, $byPath['/tree/sub/nested/c.txt']->type);
        self::assertSame(EntryType::Directory, $byPath['/tree/sub/nested']->type);
        self::assertSame(EntryType::Directory, $byPath['/tree/sub']->type);

        // Post-order invariant: every directory comes AFTER its children.
        self::assertGreaterThan($position['/tree/sub/nested/c.txt'], $position['/tree/sub/nested']);
        self::assertGreaterThan($position['/tree/sub/b.txt'], $position['/tree/sub']);
        self::assertGreaterThan($position['/tree/sub/nested'], $position['/tree/sub']);

        // Sizes only present on files.
        self::assertSame(1, $byPath['/tree/a.txt']->size);
        self::assertNull($byPath['/tree/sub']->size);
    }

    public function testWalkRejectsInvalidPath(): void
    {
        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(InvalidPathException::class);
        iterator_to_array($client->walk('../etc/passwd'), false);
    }

    public function testWalkClassifiesSymlinkAsSymlink(): void
    {
        $this->fixture->writeRemote('/tree/file.txt', 'data');
        symlink(
            $this->fixture->rootDir . '/tree/file.txt',
            $this->fixture->rootDir . '/tree/link.txt',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array($client->walk('/tree'), false);

        // Symlink yielded alongside the file, NOT recursed into.
        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        self::assertArrayHasKey('/tree/link.txt', $byPath);
        self::assertSame(EntryType::Symlink, $byPath['/tree/link.txt']->type);
        self::assertNull($byPath['/tree/link.txt']->size);
    }

    public function testWalkFollowResolvesSymlinkToFileAsFile(): void
    {
        $this->fixture->writeRemote('/tree/target.txt', 'payload');
        symlink(
            $this->fixture->rootDir . '/tree/target.txt',
            $this->fixture->rootDir . '/tree/link.txt',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        // Under Follow, the link reports as a File with the target's size.
        self::assertSame(EntryType::File, $byPath['/tree/link.txt']->type);
        self::assertSame(7, $byPath['/tree/link.txt']->size, 'size should match the target file');
        // Target itself also yielded — Follow doesn't deduplicate.
        self::assertSame(EntryType::File, $byPath['/tree/target.txt']->type);
    }

    public function testWalkFollowDescendsIntoSymlinkedDirectory(): void
    {
        // Real subtree at /tree/payload; symlink at /tree/alias points to it.
        $this->fixture->writeRemote('/tree/payload/inside.txt', 'x');
        symlink(
            $this->fixture->rootDir . '/tree/payload',
            $this->fixture->rootDir . '/tree/alias',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $paths = array_map(static fn(RemoteEntry $e): string => $e->path, $entries);

        // Walking through the symlink surfaces the target's child under
        // the LINK path — that's the point of Follow.
        self::assertContains('/tree/alias/inside.txt', $paths);
        // And under the canonical path too (both branches were visited).
        self::assertContains('/tree/payload/inside.txt', $paths);
        // The alias entry itself appears as a Directory now (not Symlink).
        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        self::assertSame(EntryType::Directory, $byPath['/tree/alias']->type);
    }

    public function testWalkFollowDetectsCycleAndDropsRepeatedTarget(): void
    {
        // Self-cycle: /tree/loop is a symlink pointing at /tree itself.
        // Without cycle detection this would re-enter /tree forever.
        $this->fixture->writeRemote('/tree/leaf.txt', 'leaf');
        symlink(
            $this->fixture->rootDir . '/tree',
            $this->fixture->rootDir . '/tree/loop',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $paths = array_map(static fn(RemoteEntry $e): string => $e->path, $entries);
        // Real leaf is reachable EXACTLY once. The exact-count assertion
        // catches a regressed "loops a few times then bails" detector —
        // a NotContains check on the loop entries would still pass for
        // those bugs.
        self::assertSame(
            ['/tree/leaf.txt'],
            array_values(array_filter($paths, static fn(string $p): bool => str_ends_with($p, 'leaf.txt'))),
        );
        // The loop link is not yielded as a Directory entry (the cycle
        // detector skipped it before we descended).
        self::assertNotContains('/tree/loop', $paths);
        // And we definitely didn't recurse into the cycle.
        self::assertNotContains('/tree/loop/leaf.txt', $paths);
    }

    public function testWalkFollowDetectsIndirectCycleThroughChildLink(): void
    {
        // Indirect cycle: /tree contains a regular subdir A; A contains a
        // symlink "back" pointing at /tree. The cycle detector seeds
        // visited with /tree's inode at the start of walk(), so when A's
        // "back" symlink resolves to /tree we trip the visited check.
        // This case proves the seeding is what catches non-self cycles —
        // a "skip every symlink target whose inode equals the CURRENT
        // dir's" implementation would miss this.
        $this->fixture->writeRemote('/tree/A/inside.txt', 'a');
        symlink(
            $this->fixture->rootDir . '/tree',
            $this->fixture->rootDir . '/tree/A/back',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $paths = array_map(static fn(RemoteEntry $e): string => $e->path, $entries);
        // The real file under A is reached exactly once.
        self::assertSame(
            ['/tree/A/inside.txt'],
            array_values(array_filter($paths, static fn(string $p): bool => str_ends_with($p, 'inside.txt'))),
        );
        // The cycle link "back" is not descended into.
        self::assertEmpty(
            array_filter($paths, static fn(string $p): bool => str_contains($p, '/back/')),
            'no entry should be reached THROUGH /tree/A/back — that\'s the cycle',
        );
    }

    public function testWalkFollowDetectsCycleNestedDeepInSubtree(): void
    {
        // Cycle within a subtree, not pointing at the walk root:
        //   /tree/A/B/loop -> /tree/A/B
        // The visited set seeds /tree (the root) but not /tree/A/B; the
        // self-cycle on /tree/A/B is detected when the second descent
        // through the symlink finds /tree/A/B's inode already in visited
        // (the first descent added it). Without cycle detection this
        // would recurse without bound; the test would time out or PHP's
        // recursion limit would blow.
        $this->fixture->writeRemote('/tree/A/B/leaf.txt', 'leaf');
        symlink(
            $this->fixture->rootDir . '/tree/A/B',
            $this->fixture->rootDir . '/tree/A/B/loop',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $paths = array_map(static fn(RemoteEntry $e): string => $e->path, $entries);
        // Real leaf reached.
        self::assertContains('/tree/A/B/leaf.txt', $paths);
        // No `/loop/loop` chain — we'd see those entries under unbounded
        // recursion.
        self::assertEmpty(
            array_filter($paths, static fn(string $p): bool => str_contains($p, '/loop/loop')),
        );
    }

    public function testWalkFollowPreservesSymlinkWhenTargetUnstatable(): void
    {
        // Dangling symlink — link exists, target doesn't. sftpStat on
        // the link's path returns false; Follow should fall back to
        // yielding the link as Symlink rather than crashing or
        // dropping it silently.
        $this->fixture->writeRemote('/tree/anchor.txt', 'a');
        symlink(
            $this->fixture->rootDir . '/tree/nonexistent-target',
            $this->fixture->rootDir . '/tree/dangling',
        );

        $client = $this->newConnectedClientWithFakeFs();
        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        self::assertArrayHasKey('/tree/dangling', $byPath);
        self::assertSame(EntryType::Symlink, $byPath['/tree/dangling']->type);
    }

    public function testWalkFollowSkipsSymlinkWhenStatLacksDevAndIno(): void
    {
        // Some legacy SFTP servers strip dev/ino out of the stat
        // response. Without those keys the cycle detector can't decide
        // whether re-entering is safe; the conservative call is to
        // skip rather than risk unbounded recursion. Simulate that
        // pathology by returning a stat array WITH a directory mode
        // but WITHOUT dev/ino keys for the link path.
        $this->fixture->writeRemote('/tree/payload/inside.txt', 'x');
        symlink(
            $this->fixture->rootDir . '/tree/payload',
            $this->fixture->rootDir . '/tree/sketchy',
        );

        $client = $this->newConnectedClientWithFakeFs(
            sftpStat: function (mixed $h, string $p): array|false {
                $real = $this->fixture->rootDir . '/' . ltrim($p, '/');
                $st = @stat($real);
                if ($st === false) {
                    return false;
                }
                // For the suspect link path only, drop dev+ino to
                // mimic a stat-poor server response.
                if ($p === '/tree/sketchy') {
                    unset($st['dev'], $st['ino']);
                    unset($st[0], $st[1]);
                }

                return $st;
            },
        );

        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $paths = array_map(static fn(RemoteEntry $e): string => $e->path, $entries);
        // The suspect link itself isn't recursed (no Directory entry
        // for it) and isn't yielded as Other / File either — the
        // skip-on-unreadable-inode branch fires.
        self::assertNotContains('/tree/sketchy', $paths);
        self::assertNotContains('/tree/sketchy/inside.txt', $paths);
        // The canonical path is still walked normally.
        self::assertContains('/tree/payload/inside.txt', $paths);
    }

    public function testWalkFollowYieldsSymlinkForUnusualTargetTypes(): void
    {
        // Symlink to a FIFO/socket/device: targetType resolves to
        // EntryType::Other, but the wrapper preserves the Symlink
        // classification rather than collapsing to Other (the caller
        // gets to see "there's a link here" without us pretending we
        // know what's behind it).
        $this->fixture->writeRemote('/tree/anchor.txt', 'a');
        symlink(
            $this->fixture->rootDir . '/tree/unusual',
            $this->fixture->rootDir . '/tree/special',
        );

        $client = $this->newConnectedClientWithFakeFs(
            sftpStat: function (mixed $h, string $p): array|false {
                $real = $this->fixture->rootDir . '/' . ltrim($p, '/');
                // For the special link, fake a FIFO mode (S_IFIFO=0o010000)
                // so the match in walkInternal falls into the `default`
                // (EntryType::Other) arm.
                if ($p === '/tree/special') {
                    return [
                        'mode' => 0o010000 | 0o644,
                        'dev' => 1,
                        'ino' => 999_999,
                        'size' => 0,
                    ];
                }
                $st = @stat($real);

                return $st === false ? false : $st;
            },
        );

        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array(
            $client->walk('/tree', \IDCT\Networking\Ssh\Directory\SymlinkPolicy::Follow),
            false,
        );

        $byPath = [];
        foreach ($entries as $e) {
            $byPath[$e->path] = $e;
        }
        self::assertArrayHasKey('/tree/special', $byPath);
        self::assertSame(EntryType::Symlink, $byPath['/tree/special']->type);
    }

    public function testWalkFallsBackToSftpStatWhenLstatUnsupported(): void
    {
        // Simulate ancient libssh2 by making the stream-wrapper's url_stat
        // unavailable for a specific entry. We can't override the wrapper's
        // mode flag handling, but we CAN make sftpStat return a known mode
        // when lstat is bypassed. Easiest: mark the URI as a stat failure
        // and verify entryType falls back to sftpStat (which we mock).
        $this->fixture->writeRemote('/tree/orphan.txt', 'data');
        $client = $this->newConnectedClientWithFakeFs();

        // Poison the lstat path so the fallback fires.
        \IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper::$statFailures['ssh2.sftp://1/tree/orphan.txt'] = true;

        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array($client->walk('/tree'), false);

        // entryType used sftpStat (mocked) which we set to return 0o100000 (file).
        $found = array_filter($entries, static fn(RemoteEntry $e): bool => $e->path === '/tree/orphan.txt');
        self::assertCount(1, $found, 'orphan.txt should be yielded via the sftpStat fallback');
        self::assertSame(EntryType::File, array_values($found)[0]->type);
    }

    public function testWalkClassifiesEntryAsOtherWhenBothStatsFail(): void
    {
        $this->fixture->writeRemote('/tree/ghost.txt', 'data');
        $client = $this->newConnectedClientWithFakeFs(
            sftpStat: fn(): false => false, // both lstat and sftpStat fail
        );

        \IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper::$statFailures['ssh2.sftp://1/tree/ghost.txt'] = true;

        /** @var list<RemoteEntry> $entries */
        $entries = iterator_to_array($client->walk('/tree'), false);
        $found = array_filter($entries, static fn(RemoteEntry $e): bool => $e->path === '/tree/ghost.txt');
        self::assertCount(1, $found);
        self::assertSame(EntryType::Other, array_values($found)[0]->type);
    }

    // ─── uploadDirectory ──────────────────────────────────────────────

    public function testUploadDirectoryRoundTripsNestedTree(): void
    {
        // Local tree (≥ 3 levels, mixed empty / non-empty dirs):
        //   src/a.txt
        //   src/sub/b.txt
        //   src/sub/deep/c.txt
        //   src/sub/empty/        (empty)
        $root = $this->fixture->rootDir . '/src';
        mkdir($root . '/sub/deep', 0o755, true);
        mkdir($root . '/sub/empty', 0o755, true);
        file_put_contents($root . '/a.txt', 'aaa');
        file_put_contents($root . '/sub/b.txt', 'bb');
        file_put_contents($root . '/sub/deep/c.txt', 'cccc');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);

        $result = $client->uploadDirectory($root, '/remote/dest');

        self::assertInstanceOf(UploadResult::class, $result);
        self::assertSame(3, $result->filesTransferred);
        self::assertSame(3 + 2 + 4, $result->bytesTransferred);
        self::assertSame([], $result->skipped);

        self::assertSame('aaa', $this->fixture->readRemote('/remote/dest/a.txt'));
        self::assertSame('bb', $this->fixture->readRemote('/remote/dest/sub/b.txt'));
        self::assertSame('cccc', $this->fixture->readRemote('/remote/dest/sub/deep/c.txt'));
        self::assertTrue(is_dir($this->fixture->rootDir . '/remote/dest/sub/empty'));
    }

    public function testUploadDirectorySkipsSymlinks(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root, 0o755, true);
        file_put_contents($root . '/file.txt', 'real');
        symlink($root . '/file.txt', $root . '/link.txt');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $result = $client->uploadDirectory($root, '/remote/dest');

        self::assertSame(1, $result->filesTransferred); // only the regular file
        self::assertCount(1, $result->skipped);
        self::assertSame($root . '/link.txt', $result->skipped[0]);
    }

    public function testUploadDirectoryRejectsMissingLocalDir(): void
    {
        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('local directory does not exist');
        $client->uploadDirectory('/no/such/path', '/remote/dest');
    }

    public function testUploadDirectoryOnEmptySourceProducesZeroCountsResult(): void
    {
        // Empty source dir: no files, no failures, no skips. Exercises
        // the `max(0, $files)` / `max(0, $bytes)` clamps on the
        // UploadResult constructor where both arguments are 0.
        $root = $this->fixture->rootDir . '/empty-src';
        mkdir($root);

        $client = $this->newConnectedClientWithFakeFs();
        $result = $client->uploadDirectory($root, '/data/dest');

        self::assertSame(0, $result->filesTransferred);
        self::assertSame(0, $result->bytesTransferred);
        self::assertSame([], $result->skipped);
        self::assertSame([], $result->failures);
    }

    public function testDownloadDirectoryOnEmptyRemoteProducesZeroCountsResult(): void
    {
        // Empty remote dir: same shape as above but for the
        // DownloadResult clamp pair on the download path.
        mkdir($this->fixture->rootDir . '/data/empty-dest', 0o755, true);
        $localDest = $this->fixture->rootDir . '/dl-empty';

        $client = $this->newConnectedClientWithFakeFs();
        $result = $client->downloadDirectory('/data/empty-dest', $localDest);

        self::assertSame(0, $result->filesTransferred);
        self::assertSame(0, $result->bytesTransferred);
        self::assertSame([], $result->skipped);
        self::assertSame([], $result->failures);
    }

    public function testUploadDirectoryRejectsInvalidRemotePath(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root);
        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(InvalidPathException::class);
        $client->uploadDirectory($root, '../etc');
    }

    public function testUploadDirectoryCreatesRemoteRootWhenMissing(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root);
        file_put_contents($root . '/x.txt', '1');

        $client = $this->newConnectedClientWithFakeFs(atomic: false);
        $client->uploadDirectory($root, '/fresh/remote/root');

        self::assertTrue(is_dir($this->fixture->rootDir . '/fresh/remote/root'));
        self::assertSame('1', $this->fixture->readRemote('/fresh/remote/root/x.txt'));
    }

    public function testUploadDirectoryDoesNotCreateRemoteRootWhenFlagIsFalse(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root);
        file_put_contents($root . '/x.txt', '1');
        // Pre-create the remote root manually so the upload still succeeds —
        // we just want to verify createRemoteDir=false doesn't mkdir it for us.
        mkdir($this->fixture->rootDir . '/preexisting', 0o755);

        $mkdirCalls = 0;
        $client = $this->newConnectedClientWithFakeFs(
            atomic: false,
            onMkdir: function () use (&$mkdirCalls): void {
                $mkdirCalls++;
            },
        );

        $client->uploadDirectory($root, '/preexisting', createRemoteDir: false);

        // Only the per-subdir mkdirs (zero in this case — root has no subdirs)
        // should fire. With the root flag false, the toplevel mkdir is skipped.
        self::assertSame(0, $mkdirCalls);
    }

    public function testUploadDirectoryRaisesWhenSftpMkdirFails(): void
    {
        $root = $this->fixture->rootDir . '/src';
        mkdir($root . '/sub', 0o755, true);
        file_put_contents($root . '/sub/x.txt', '1');

        $client = $this->newConnectedClientWithFakeFs(
            atomic: false,
            sftpMkdir: fn(): false => false,
        );

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('unable to create remote directory');
        $client->uploadDirectory($root, '/remote');
    }

    // ─── downloadDirectory ────────────────────────────────────────────

    public function testDownloadDirectoryRoundTripsNestedTree(): void
    {
        $this->fixture->writeRemote('/source/a.txt', 'aaa');
        $this->fixture->writeRemote('/source/sub/b.txt', 'bb');
        $this->fixture->writeRemote('/source/sub/deep/c.txt', 'cccc');
        mkdir($this->fixture->rootDir . '/source/sub/empty', 0o755);

        $localDest = $this->fixture->rootDir . '/dest';
        $client = $this->newConnectedClientWithFakeFs();

        $result = $client->downloadDirectory('/source', $localDest);

        self::assertInstanceOf(DownloadResult::class, $result);
        self::assertSame(3, $result->filesTransferred);
        self::assertSame(3 + 2 + 4, $result->bytesTransferred);
        self::assertSame([], $result->skipped);
        self::assertSame('aaa', file_get_contents($localDest . '/a.txt'));
        self::assertSame('bb', file_get_contents($localDest . '/sub/b.txt'));
        self::assertSame('cccc', file_get_contents($localDest . '/sub/deep/c.txt'));
        self::assertTrue(is_dir($localDest . '/sub/empty'));
    }

    public function testDownloadDirectorySkipsRemoteSymlinks(): void
    {
        $this->fixture->writeRemote('/source/regular.txt', 'data');
        symlink(
            $this->fixture->rootDir . '/source/regular.txt',
            $this->fixture->rootDir . '/source/link.txt',
        );

        $localDest = $this->fixture->rootDir . '/dest';
        $client = $this->newConnectedClientWithFakeFs();

        $result = $client->downloadDirectory('/source', $localDest);

        self::assertSame(1, $result->filesTransferred);
        self::assertSame(['/source/link.txt'], $result->skipped);
        self::assertFileDoesNotExist($localDest . '/link.txt');
    }

    public function testDownloadDirectoryCreatesLocalDestWhenMissing(): void
    {
        $this->fixture->writeRemote('/source/x.txt', 'x');
        $localDest = $this->fixture->rootDir . '/nested/under/here';

        $client = $this->newConnectedClientWithFakeFs();
        $client->downloadDirectory('/source', $localDest);

        self::assertFileExists($localDest . '/x.txt');
    }

    public function testDownloadDirectoryRejectsInvalidRemotePath(): void
    {
        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(InvalidPathException::class);
        $client->downloadDirectory('../etc/passwd', $this->fixture->rootDir . '/dest');
    }

    public function testDownloadDirectoryFailsWhenLocalDirCannotBeCreated(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }
        $unwritable = $this->fixture->rootDir . '/ro';
        mkdir($unwritable, 0o555);

        try {
            $client = $this->newConnectedClientWithFakeFs();
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('could not be created');
            $client->downloadDirectory('/source', $unwritable . '/child');
        } finally {
            chmod($unwritable, 0o755);
        }
    }

    public function testDownloadDirectoryRaisesWhenLocalMkdirFailsMidWalk(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }
        $this->fixture->writeRemote('/source/sub/x.txt', 'x');

        $client = $this->newConnectedClientWithFakeFs();

        // Local dest exists, but is read-only — so the mid-walk mkdir for
        // "sub" should trip the RemoteFilesystemException branch.
        $localDest = $this->fixture->rootDir . '/dest';
        mkdir($localDest, 0o555);

        try {
            $this->expectException(RemoteFilesystemException::class);
            $this->expectExceptionMessage('unable to create local directory');
            $client->downloadDirectory('/source', $localDest);
        } finally {
            chmod($localDest, 0o755);
        }
    }

    // ─── removeDirectoryTree ──────────────────────────────────────────

    public function testRemoveDirectoryTreeRemovesNestedTree(): void
    {
        $this->fixture->writeRemote('/tree/a.txt', 'A');
        $this->fixture->writeRemote('/tree/sub/b.txt', 'B');
        $this->fixture->writeRemote('/tree/sub/nested/c.txt', 'C');
        mkdir($this->fixture->rootDir . '/tree/sub/empty', 0o755);

        $client = $this->newConnectedClientWithFakeFs();
        self::assertSame($client, $client->removeDirectoryTree('/tree'));

        self::assertFalse(is_dir($this->fixture->rootDir . '/tree'));
    }

    public function testRemoveDirectoryTreeUnlinksSymlinks(): void
    {
        $this->fixture->writeRemote('/tree/regular.txt', 'data');
        symlink(
            $this->fixture->rootDir . '/tree/regular.txt',
            $this->fixture->rootDir . '/tree/link.txt',
        );

        $client = $this->newConnectedClientWithFakeFs();
        $client->removeDirectoryTree('/tree');

        self::assertFalse(file_exists($this->fixture->rootDir . '/tree'));
    }

    public function testRemoveDirectoryTreeRaisesWhenUnlinkRefused(): void
    {
        $this->fixture->writeRemote('/tree/x.txt', 'x');

        $client = $this->newConnectedClientWithFakeFs(
            sftpUnlink: fn(): false => false,
        );

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('unable to remove remote entry');
        $client->removeDirectoryTree('/tree');
    }

    public function testRemoveDirectoryTreeRaisesWhenChildRmdirRefused(): void
    {
        // Nested empty directory; the inner rmdir is rejected.
        mkdir($this->fixture->rootDir . '/tree/inner', 0o755, true);

        $client = $this->newConnectedClientWithFakeFs(
            sftpRmdir: fn(): false => false,
        );

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('unable to remove remote directory');
        $client->removeDirectoryTree('/tree');
    }

    public function testRemoveDirectoryTreeRaisesWhenRootRmdirRefused(): void
    {
        // Empty dir — child recursion does nothing, the final rmdir on the
        // root must surface the failure.
        mkdir($this->fixture->rootDir . '/tree', 0o755);

        $client = $this->newConnectedClientWithFakeFs(
            sftpRmdir: fn(): false => false,
        );

        $this->expectException(RemoteFilesystemException::class);
        $this->expectExceptionMessage('unable to remove remote directory /tree');
        $client->removeDirectoryTree('/tree');
    }

    public function testRemoveDirectoryTreeRejectsInvalidPath(): void
    {
        $client = $this->newConnectedClientWithFakeFs();
        $this->expectException(InvalidPathException::class);
        $client->removeDirectoryTree('../etc');
    }

    // ─── before-connect guards: each public directory entry-point must
    // call requireSftp() up front so callers see a typed
    // ConnectionException, not a lazier downstream error. ──────────────

    public function testWalkBeforeConnectThrowsConnectionException(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $this->expectException(\IDCT\Networking\Ssh\Exception\ConnectionException::class);
        // walk() is a generator; the requireSftp() guard must fire BEFORE
        // the generator is constructed so callers don't have to start
        // iterating just to find out the client isn't connected.
        $client->walk('/tree');
    }

    public function testUploadDirectoryBeforeConnectThrowsConnectionException(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $localDir = sys_get_temp_dir() . '/sftp-test-' . bin2hex(random_bytes(4));
        mkdir($localDir);
        try {
            $this->expectException(\IDCT\Networking\Ssh\Exception\ConnectionException::class);
            $client->uploadDirectory($localDir, '/tree');
        } finally {
            @rmdir($localDir);
        }
    }

    public function testDownloadDirectoryBeforeConnectThrowsConnectionException(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $localDir = sys_get_temp_dir() . '/sftp-test-' . bin2hex(random_bytes(4));
        $this->expectException(\IDCT\Networking\Ssh\Exception\ConnectionException::class);
        try {
            $client->downloadDirectory('/tree', $localDir);
        } finally {
            @rmdir($localDir);
        }
    }

    public function testRemoveDirectoryTreeBeforeConnectThrowsConnectionException(): void
    {
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $this->expectException(\IDCT\Networking\Ssh\Exception\ConnectionException::class);
        $client->removeDirectoryTree('/tree');
    }

    // ─── helpers ───────────────────────────────────────────────────────

    /**
     * Wires the Ssh2FunctionsInterface mock so sftp* primitives operate on
     * the SftpFixture tmpdir. Optional callables override individual methods
     * for failure-injection tests.
     *
     * @param (callable(mixed, string, int, bool): bool)|null $sftpMkdir
     * @param (callable(mixed, string): bool)|null $sftpRmdir
     * @param (callable(mixed, string): bool)|null $sftpUnlink
     * @param (callable(mixed, string): array<int|string, int>|false)|null $sftpStat
     * @param (callable(mixed, string): void)|null $onMkdir spy hook
     */
    private function newConnectedClientWithFakeFs(
        bool $atomic = false,
        ?callable $sftpMkdir = null,
        ?callable $sftpRmdir = null,
        ?callable $sftpUnlink = null,
        ?callable $sftpStat = null,
        ?callable $onMkdir = null,
    ): SftpClient {
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
            $sftpMkdir ?? function (mixed $h, string $p, int $mode, bool $recursive) use ($abs, $onMkdir): bool {
                if ($onMkdir !== null) {
                    $onMkdir($h, $p);
                }

                return @mkdir($abs($p), $mode, $recursive) || is_dir($abs($p));
            },
        );
        $this->ssh2->method('sftpRmdir')->willReturnCallback(
            $sftpRmdir ?? static fn(mixed $h, string $p): bool => @rmdir($abs($p)),
        );
        $this->ssh2->method('sftpUnlink')->willReturnCallback(
            $sftpUnlink ?? static fn(mixed $h, string $p): bool => @unlink($abs($p)),
        );
        $this->ssh2->method('sftpStat')->willReturnCallback(
            $sftpStat ?? static function (mixed $h, string $p) use ($abs): array|false {
                $real = $abs($p);
                if (! file_exists($real)) {
                    return false;
                }
                $stat = stat($real);

                // Normalise to the ssh2_sftp_stat shape — keyed array with
                // the numeric + named entries. PHP's stat() already returns both.
                return $stat === false ? false : $stat;
            },
        );

        $client->connect('example.com');

        return $client;
    }
}
