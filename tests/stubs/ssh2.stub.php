<?php

declare(strict_types=1);

/**
 * Stub definitions for ext-ssh2 1.4+ — registered via phpstan's `stubFiles:`.
 *
 * PHPStan parses the signatures and overrides the (outdated, resource-based)
 * bundled stubs from JetBrains/phpstorm-stubs. Never executed at runtime —
 * function bodies throw to satisfy any declared return type.
 */

const SSH2_FINGERPRINT_MD5 = 0;
const SSH2_FINGERPRINT_SHA1 = 1;
const SSH2_FINGERPRINT_SHA256 = 2;
const SSH2_FINGERPRINT_HEX = 0;
const SSH2_FINGERPRINT_RAW = 16;
const SSH2_TERM_UNIT_CHARS = 0;
const SSH2_TERM_UNIT_PIXELS = 1;
const SSH2_DEFAULT_TERM_WIDTH = 80;
const SSH2_DEFAULT_TERM_HEIGHT = 25;
const SSH2_DEFAULT_TERMINAL = 'vanilla';

/**
 * @param array<string, mixed>|null $methods
 * @param array<string, mixed>|null $callbacks
 * @return object|false
 */
function ssh2_connect(string $host, int $port = 22, ?array $methods = null, ?array $callbacks = null)
{
    throw new \LogicException('stub');
}

function ssh2_disconnect(object $session): bool
{
    throw new \LogicException('stub');
}

function ssh2_fingerprint(object $session, int $flags = 0): string
{
    throw new \LogicException('stub');
}

/**
 * @return bool|array<int, string>
 */
function ssh2_auth_none(object $session, string $username)
{
    throw new \LogicException('stub');
}

function ssh2_auth_password(object $session, string $username, string $password): bool
{
    throw new \LogicException('stub');
}

function ssh2_auth_pubkey_file(
    object $session,
    string $username,
    string $public_key_file,
    string $private_key_file,
    string $passphrase = ''
): bool {
    throw new \LogicException('stub');
}

/**
 * @return object|false
 */
function ssh2_sftp(object $session)
{
    throw new \LogicException('stub');
}

/**
 * @return array<int|string, int>|false stat()-format array (numeric 0..12 keys plus dev/ino/mode/... string keys)
 */
function ssh2_sftp_stat(object $sftp, string $path)
{
    throw new \LogicException('stub');
}

function ssh2_sftp_mkdir(object $sftp, string $dirname, int $mode = 0o777, bool $recursive = false): bool
{
    throw new \LogicException('stub');
}

function ssh2_sftp_rmdir(object $sftp, string $dirname): bool
{
    throw new \LogicException('stub');
}

function ssh2_sftp_unlink(object $sftp, string $filename): bool
{
    throw new \LogicException('stub');
}

function ssh2_sftp_rename(object $sftp, string $from, string $to): bool
{
    throw new \LogicException('stub');
}

function ssh2_scp_recv(object $session, string $remote_file, string $local_file): bool
{
    throw new \LogicException('stub');
}

function ssh2_scp_send(object $session, string $local_file, string $remote_file, int $create_mode = 0o644): bool
{
    throw new \LogicException('stub');
}

/**
 * @param array<string, string>|null $env
 * @return resource|bool
 */
function ssh2_exec(
    object $session,
    string $command,
    ?string $pty = null,
    ?array $env = null,
    int $width = 80,
    int $height = 25,
    int $width_height_type = 0
) {
    throw new \LogicException('stub');
}
