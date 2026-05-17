<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Ssh2;

/**
 * Default {@see Ssh2FunctionsInterface} implementation backed by ext-ssh2.
 *
 * Every method is a one-line delegation to the corresponding ssh2_* function.
 * Handles flow through as `mixed` because PHP has no `resource` type hint;
 * see the interface docblock for the rationale.
 */
final class Ssh2Functions implements Ssh2FunctionsInterface
{
    // Every ssh2_* call carries `@` because ext-ssh2 emits E_WARNING on every
    // recoverable false-return (auth rejected, file missing, peer torn down,
    // permission denied). Without suppression those warnings escape to global
    // error handlers (PHPUnit/Behat both convert warnings → exceptions) and
    // prevent our typed exceptions from being thrown. The suppression here is
    // the entire reason the wrapper layer exists; callers see typed
    // exceptions, not raw PHP warnings.

    public function connect(string $host, int $port, ?array $methods = null, ?array $callbacks = null): mixed
    {
        return @ssh2_connect($host, $port, $methods ?? [], $callbacks ?? []);
    }

    public function fingerprint(mixed $session, int $flags): string|false
    {
        return @ssh2_fingerprint($session, $flags);
    }

    public function authNone(mixed $session, string $username): bool
    {
        $result = @ssh2_auth_none($session, $username);

        return $result === true;
    }

    public function authPassword(mixed $session, string $username, string $password): bool
    {
        return @ssh2_auth_password($session, $username, $password);
    }

    public function authPublicKey(
        mixed $session,
        string $username,
        string $publicKey,
        string $privateKey,
        ?string $passphrase = null,
    ): bool {
        return @ssh2_auth_pubkey_file($session, $username, $publicKey, $privateKey, $passphrase ?? '');
    }

    public function sftp(mixed $session): mixed
    {
        return @ssh2_sftp($session);
    }

    /** @return array<int|string, int>|false */
    public function sftpStat(mixed $sftp, string $path): array|false
    {
        return @ssh2_sftp_stat($sftp, $path);
    }

    public function sftpMkdir(mixed $sftp, string $path, int $mode, bool $recursive): bool
    {
        return @ssh2_sftp_mkdir($sftp, $path, $mode, $recursive);
    }

    public function sftpRmdir(mixed $sftp, string $path): bool
    {
        return @ssh2_sftp_rmdir($sftp, $path);
    }

    public function sftpUnlink(mixed $sftp, string $path): bool
    {
        return @ssh2_sftp_unlink($sftp, $path);
    }

    public function sftpRename(mixed $sftp, string $from, string $to): bool
    {
        return @ssh2_sftp_rename($sftp, $from, $to);
    }

    public function scpRecv(mixed $session, string $remotePath, string $localPath): bool
    {
        return @ssh2_scp_recv($session, $remotePath, $localPath);
    }

    public function scpSend(mixed $session, string $localPath, string $remotePath, int $mode): bool
    {
        return @ssh2_scp_send($session, $localPath, $remotePath, $mode);
    }

    public function disconnect(mixed $session): bool
    {
        return @ssh2_disconnect($session);
    }

    public function sftpStreamUri(mixed $sftp, string $path): string
    {
        // ext-ssh2 returns a resource (or — in a hypothetical future release — an
        // opaque object). `intval()` yields the resource id in both regimes and
        // is the documented workaround for PHP bug #71376 where `(string)$res`
        // produces "Resource id #N" and breaks the URI.
        return 'ssh2.sftp://' . intval($sftp) . '/' . ltrim($path, '/');
    }
}
