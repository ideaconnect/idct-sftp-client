<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Path;

use IDCT\Networking\Ssh\Exception\InvalidPathException;

/**
 * Validates and joins remote-side path strings.
 *
 * Public so consumers can reuse the same validation rules outside the
 * client (e.g., in a controller validating user input before passing it
 * to `SftpClient::upload()`).
 *
 * ## Threat coverage
 *
 * - T1 path traversal — rejects components equal to `..` or `.`
 * - T2 null-byte injection — rejects `\0` anywhere in the path
 * - T3 CR/LF injection — rejects `\r`/`\n` and any other C0/C1 control char
 * - T4 length overflow — caps at {@see self::DEFAULT_MAX_LENGTH} bytes
 *   (configurable per call)
 * - T5 `.` / `..` as exact filename — same rule as T1
 * - T6 absolute-vs-relative prefix confusion — codified in
 *   {@see joinRemote()}: an absolute path bypasses the prefix
 *
 * The 6-threat matrix corresponds to §P2 of PRODUCTION_GRADE.md.
 *
 * ## What this class does NOT do
 *
 * - It does NOT canonicalize (`realpath`-style) the path. Servers normalize
 *   themselves; we just refuse to send obviously malicious input.
 * - It does NOT validate the path exists on the remote — that's an I/O
 *   concern handled elsewhere.
 * - It does NOT validate local-side filesystem paths. Local paths are
 *   constructed by the application and assumed trusted; if you accept
 *   untrusted input for local paths, validate it upstream.
 */
final class PathValidator
{
    /**
     * Per-call length cap. Generous default — most SFTP servers and POSIX
     * filesystems accept up to a few KiB. Set lower in calling code if the
     * target server is known to enforce stricter limits.
     */
    public const DEFAULT_MAX_LENGTH = 4096;

    /**
     * Validate a remote path string.
     *
     * @param int<1, max> $maxLength
     * @return string the path unchanged (returned for fluent use)
     *
     * @throws InvalidPathException if any rule rejects the input
     */
    public static function validateRemotePath(
        string $path,
        bool $allowAbsolute = true,
        int $maxLength = self::DEFAULT_MAX_LENGTH,
    ): string {
        if ($path === '') {
            throw new InvalidPathException('Remote path must not be empty.');
        }
        if (\strlen($path) > $maxLength) {
            throw new InvalidPathException(\sprintf(
                'Remote path exceeds %d bytes (%d given).',
                $maxLength,
                \strlen($path),
            ));
        }
        if (str_contains($path, "\0")) {
            throw new InvalidPathException('Remote path contains a null byte.');
        }
        // Reject CR/LF specifically (for clear error messages) and any other
        // C0/DEL control character.
        if (str_contains($path, "\r") || str_contains($path, "\n")) {
            throw new InvalidPathException('Remote path contains a CR or LF character.');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            throw new InvalidPathException('Remote path contains a control character.');
        }

        $isAbsolute = $path[0] === '/';
        if ($isAbsolute && ! $allowAbsolute) {
            throw new InvalidPathException(
                'Absolute remote path not permitted here; supply a relative path.',
            );
        }

        // Path traversal check — any component equal to '.' or '..' is rejected.
        // We explode on '/' and skip the leading empty string for absolute paths.
        foreach (explode('/', $path) as $component) {
            if ($component === '..' || $component === '.') {
                throw new InvalidPathException(
                    'Remote path component "' . $component . '" is not permitted (traversal).',
                );
            }
        }

        return $path;
    }

    /**
     * Join a remote prefix with a caller-supplied path, validating the
     * result.
     *
     * Semantics:
     * - If `$path` is absolute (starts with `/`), the prefix is **bypassed**
     *   and `$path` is returned verbatim. This codifies the "T6 prefix
     *   confusion" rule — an absolute path explicitly opts out of the
     *   prefix, rather than being silently concatenated.
     * - If `$path` is relative, the result is `$prefix . $path`.
     *
     * The joined result is then re-validated, so attackers cannot smuggle
     * traversal sequences through the prefix (e.g., prefix `/safe/` +
     * path `../etc/passwd` produces `/safe/../etc/passwd`, which contains
     * a `..` component and is rejected).
     *
     * @throws InvalidPathException
     */
    public static function joinRemote(string $prefix, string $path): string
    {
        // Validate the caller-supplied path first so error messages point at
        // the right input.
        self::validateRemotePath($path);

        $joined = ($path[0] === '/') ? $path : $prefix . $path;

        // Re-validate the joined result so a malicious prefix + a sneaky
        // relative path can't compose into something dangerous.
        return self::validateRemotePath($joined);
    }
}
