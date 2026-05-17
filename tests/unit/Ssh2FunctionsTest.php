<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Ssh2\Ssh2Functions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The Ssh2Functions adapter is a one-line delegation shim; every ssh2_* method
 * is exercised end-to-end by the Behat functional suite against a real SFTP
 * server. The one piece with non-trivial pure logic — URI construction in
 * sftpStreamUri — is covered here using a real PHP resource so intval() does
 * the right thing.
 */
#[CoversClass(Ssh2Functions::class)]
final class Ssh2FunctionsTest extends TestCase
{
    public function testSftpStreamUriBuildsExpectedPath(): void
    {
        $adapter = new Ssh2Functions();
        $fakeHandle = fopen('php://memory', 'r+');
        self::assertNotFalse($fakeHandle);

        try {
            $expectedId = (int) $fakeHandle;
            self::assertSame(
                "ssh2.sftp://{$expectedId}/var/upload/file.bin",
                $adapter->sftpStreamUri($fakeHandle, '/var/upload/file.bin'),
            );
        } finally {
            fclose($fakeHandle);
        }
    }

    public function testSftpStreamUriStripsLeadingSlashFromPath(): void
    {
        $adapter = new Ssh2Functions();
        $fakeHandle = fopen('php://memory', 'r+');
        self::assertNotFalse($fakeHandle);

        try {
            $expectedId = (int) $fakeHandle;
            self::assertSame(
                "ssh2.sftp://{$expectedId}/foo/bar",
                $adapter->sftpStreamUri($fakeHandle, '////foo/bar'),
            );
        } finally {
            fclose($fakeHandle);
        }
    }
}
