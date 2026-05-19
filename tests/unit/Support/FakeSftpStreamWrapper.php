<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Support;

/**
 * Test-only stream wrapper that maps `ssh2.sftp://N/path` URIs onto a local
 * temp directory so SftpClient's download/upload code paths exercise real
 * stream copy semantics without needing an SSH server.
 *
 * The wrapper is registered/restored per test via {@see SftpFixture}.
 */
final class FakeSftpStreamWrapper
{
    public static string $rootDir = '';

    /** @var array<string, bool> Map of URIs that should fail to open (read or write). */
    public static array $openFailures = [];

    /** @var array<string, bool> Map of paths that should be reported as missing by url_stat. */
    public static array $statFailures = [];

    /** @var array<string, bool> Map of URIs whose stream_read should always return false. */
    public static array $readFailures = [];

    /** @var array<string, bool> Map of URIs whose stream_write should always return false. */
    public static array $writeFailures = [];

    /** @var resource|null */
    public $context = null;

    /** @var resource|false */
    private mixed $handle = false;

    /** @var resource|false */
    private mixed $dirHandle = false;

    private string $openedUri = '';

    public static function reset(string $rootDir): void
    {
        self::$rootDir = $rootDir;
        self::$openFailures = [];
        self::$statFailures = [];
        self::$readFailures = [];
        self::$writeFailures = [];
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool
    {
        if (isset(self::$openFailures[$path])) {
            return false;
        }

        $this->openedUri = $path;
        $local = $this->toLocal($path);
        $this->ensureParent($local);
        $this->handle = @fopen($local, $mode);

        return $this->handle !== false;
    }

    public function stream_read(int $count): string|false
    {
        if ($this->handle === false) {
            return false;
        }
        if (isset(self::$readFailures[$this->openedUri])) {
            return false;
        }

        return fread($this->handle, $count);
    }

    public function stream_write(string $data): int
    {
        if ($this->handle === false) {
            return 0;
        }
        if (isset(self::$writeFailures[$this->openedUri])) {
            // Returning 0 (less than $data length) signals "no progress" to
            // stream_copy_to_stream and aborts the copy with false.
            return 0;
        }
        $written = fwrite($this->handle, $data);

        return $written === false ? 0 : $written;
    }

    public function stream_eof(): bool
    {
        return $this->handle === false || feof($this->handle);
    }

    public function stream_close(): void
    {
        if ($this->handle !== false) {
            fclose($this->handle);
            $this->handle = false;
        }
    }

    public function stream_tell(): int
    {
        if ($this->handle === false) {
            return 0;
        }
        $pos = ftell($this->handle);

        return $pos === false ? 0 : $pos;
    }

    public function stream_seek(int $offset, int $whence = SEEK_SET): bool
    {
        if ($this->handle === false) {
            return false;
        }

        return fseek($this->handle, $offset, $whence) === 0;
    }

    /**
     * @return array<int|string, int>|false
     */
    public function stream_stat(): array|false
    {
        if ($this->handle === false) {
            return false;
        }

        return fstat($this->handle);
    }

    /**
     * @return array<int|string, int>|false
     */
    public function url_stat(string $path, int $flags): array|false
    {
        if (isset(self::$statFailures[$path])) {
            return false;
        }

        $local = $this->toLocal($path);
        // is_link() catches dangling symlinks too (file_exists follows
        // links and returns false on broken ones, which would
        // mis-report the link as "missing" for lstat-style calls).
        if (! file_exists($local) && ! is_link($local)) {
            return false;
        }

        return ($flags & STREAM_URL_STAT_LINK) === STREAM_URL_STAT_LINK
            ? lstat($local)
            : stat($local);
    }

    public function dir_opendir(string $path, int $options): bool
    {
        if (isset(self::$openFailures[$path])) {
            return false;
        }

        $local = $this->toLocal($path);
        if (! is_dir($local)) {
            return false;
        }

        $this->dirHandle = opendir($local);

        return $this->dirHandle !== false;
    }

    public function dir_readdir(): string|false
    {
        if ($this->dirHandle === false) {
            return false;
        }

        return readdir($this->dirHandle);
    }

    public function dir_closedir(): bool
    {
        if ($this->dirHandle === false) {
            return false;
        }
        closedir($this->dirHandle);
        $this->dirHandle = false;

        return true;
    }

    private function toLocal(string $uri): string
    {
        // "ssh2.sftp://123/some/path" -> "$rootDir/some/path"
        $parsed = parse_url($uri);
        $rawPath = $parsed['path'] ?? '';

        return rtrim(self::$rootDir, '/') . '/' . ltrim($rawPath, '/');
    }

    private function ensureParent(string $localPath): void
    {
        $dir = \dirname($localPath);
        if (! is_dir($dir)) {
            @mkdir($dir, 0o755, true);
        }
    }
}
