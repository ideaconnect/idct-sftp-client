<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Ssh2;

/**
 * Thin seam over the procedural ext-ssh2 API.
 *
 * Lets the rest of the library call typed methods, and lets unit tests mock
 * every call without loading ext-ssh2. Implementations must NOT add behaviour
 * beyond one-to-one delegation to the underlying ssh2_* function.
 *
 * ## A note on session/sftp handle types
 *
 * ext-ssh2 1.4.x — the floor we ship against — still returns PHP `resource`s
 * (`SSH2 Session`, `SSH2 SFTP`) from `ssh2_connect()` and `ssh2_sftp()`. PHP
 * has no `resource` type hint, so handles flow as `mixed` and are documented
 * via `@param resource` / `@return resource|false`. A future ext-ssh2 may
 * return opaque objects instead; both shapes round-trip through `mixed` and
 * `intval()` (the latter yields the resource id under both regimes).
 *
 * @phpstan-type Ssh2Methods array{
 *     kex?: string,
 *     hostkey?: string,
 *     client_to_server?: array{crypt?: string, comp?: string, mac?: string},
 *     server_to_client?: array{crypt?: string, comp?: string, mac?: string}
 * }
 * @phpstan-type Ssh2Callbacks array{
 *     ignore?: callable,
 *     debug?: callable,
 *     macerror?: callable,
 *     disconnect?: callable
 * }
 */
interface Ssh2FunctionsInterface
{
    /**
     * @param Ssh2Methods|null $methods
     * @param Ssh2Callbacks|null $callbacks
     * @return resource|false
     */
    public function connect(string $host, int $port, ?array $methods = null, ?array $callbacks = null): mixed;

    /** @param resource $session */
    public function fingerprint(mixed $session, int $flags): string|false;

    /** @param resource $session */
    public function authNone(mixed $session, string $username): bool;

    /** @param resource $session */
    public function authPassword(mixed $session, string $username, string $password): bool;

    /** @param resource $session */
    public function authPublicKey(
        mixed $session,
        string $username,
        string $publicKey,
        string $privateKey,
        ?string $passphrase = null,
    ): bool;

    /**
     * @param resource $session
     * @return resource|false
     */
    public function sftp(mixed $session): mixed;

    /**
     * @param resource $sftp
     * @return array<int|string, int>|false stat()-format array (numeric 0..12 keys plus dev/ino/mode/... string keys)
     */
    public function sftpStat(mixed $sftp, string $path): array|false;

    /** @param resource $sftp */
    public function sftpMkdir(mixed $sftp, string $path, int $mode, bool $recursive): bool;

    /** @param resource $sftp */
    public function sftpRmdir(mixed $sftp, string $path): bool;

    /** @param resource $sftp */
    public function sftpUnlink(mixed $sftp, string $path): bool;

    /** @param resource $sftp */
    public function sftpRename(mixed $sftp, string $from, string $to): bool;

    /** @param resource $session */
    public function scpRecv(mixed $session, string $remotePath, string $localPath): bool;

    /** @param resource $session */
    public function scpSend(mixed $session, string $localPath, string $remotePath, int $mode): bool;

    /** @param resource $session */
    public function disconnect(mixed $session): bool;

    /**
     * Build a stream-wrapper URI for the SFTP filesystem.
     * Lives on the adapter so tests can verify the produced URI by string equality.
     *
     * @param resource $sftp
     */
    public function sftpStreamUri(mixed $sftp, string $path): string;
}
