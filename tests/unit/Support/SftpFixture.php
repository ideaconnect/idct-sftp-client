<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Support;

/**
 * Per-test setup/teardown for the FakeSftpStreamWrapper and a scratch temp
 * directory that backs `ssh2.sftp://` URIs in unit tests.
 */
final class SftpFixture
{
    public readonly string $rootDir;

    public function __construct()
    {
        $this->rootDir = sys_get_temp_dir() . '/idct-sftp-test-' . bin2hex(random_bytes(6));
        mkdir($this->rootDir, 0o755, true);

        FakeSftpStreamWrapper::reset($this->rootDir);

        if (in_array('ssh2.sftp', stream_get_wrappers(), true)) {
            stream_wrapper_unregister('ssh2.sftp');
        }
        stream_wrapper_register('ssh2.sftp', FakeSftpStreamWrapper::class);
    }

    public function __destruct()
    {
        if (in_array('ssh2.sftp', stream_get_wrappers(), true)) {
            stream_wrapper_unregister('ssh2.sftp');
        }
        // The original ext-ssh2 wrapper (if loaded) will re-register itself
        // lazily on next ssh2_sftp() call; nothing to restore here.

        $this->removeDir($this->rootDir);
    }

    public function writeRemote(string $relativePath, string $contents): void
    {
        $abs = $this->rootDir . '/' . ltrim($relativePath, '/');
        $dir = \dirname($abs);
        if (! is_dir($dir)) {
            mkdir($dir, 0o755, true);
        }
        file_put_contents($abs, $contents);
    }

    public function readRemote(string $relativePath): string|false
    {
        return @file_get_contents($this->rootDir . '/' . ltrim($relativePath, '/'));
    }

    public function remoteExists(string $relativePath): bool
    {
        return file_exists($this->rootDir . '/' . ltrim($relativePath, '/'));
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }
        @rmdir($dir);
    }
}
