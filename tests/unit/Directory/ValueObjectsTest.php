<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Directory;

use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\EntryType;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\UploadResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Tiny sanity tests for the P3 Directory value objects. Exercises the
 * promoted constructors directly so the readonly property assignments
 * appear in coverage independently of the SftpClient flow.
 */
#[CoversClass(RemoteEntry::class)]
#[CoversClass(UploadResult::class)]
#[CoversClass(DownloadResult::class)]
final class ValueObjectsTest extends TestCase
{
    public function testRemoteEntryHoldsFields(): void
    {
        $e = new RemoteEntry('/a/b.txt', EntryType::File, 42);
        self::assertSame('/a/b.txt', $e->path);
        self::assertSame(EntryType::File, $e->type);
        self::assertSame(42, $e->size);

        $d = new RemoteEntry('/a/b', EntryType::Directory);
        self::assertNull($d->size, 'size defaults to null for non-files');
    }

    public function testUploadResultHoldsCounts(): void
    {
        $r = new UploadResult(3, 42, ['/local/a', '/local/b']);
        self::assertSame(3, $r->filesTransferred);
        self::assertSame(42, $r->bytesTransferred);
        self::assertSame(['/local/a', '/local/b'], $r->skipped);

        $empty = new UploadResult(0, 0);
        self::assertSame([], $empty->skipped, 'skipped defaults to []');
    }

    public function testDownloadResultHoldsCounts(): void
    {
        $r = new DownloadResult(7, 999, ['/r/a']);
        self::assertSame(7, $r->filesTransferred);
        self::assertSame(999, $r->bytesTransferred);
        self::assertSame(['/r/a'], $r->skipped);

        $empty = new DownloadResult(0, 0);
        self::assertSame([], $empty->skipped);
    }
}
