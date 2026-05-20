<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Checksum;

use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;

/**
 * Computes a remote digest by exec'ing a shell sum binary
 * (`sha256sum`, `sha1sum`, `md5sum`, …) over SSH. Assumes:
 *  - the server allows `ssh2_exec` (no `ForceCommand` lockdown);
 *  - the chosen binary is on the user's PATH;
 *  - the user has read access to the target file.
 *
 * Output format is the standard `sumcommand` two-field line:
 * `<hex-digest>  <path>`. Anything else trips a TransferException so a
 * misconfigured environment (binary missing, busybox quirk) fails
 * loudly rather than silently passing wrong fingerprints.
 *
 * For environments without shell access, use
 * {@see RedownloadRemoteHasher} or implement
 * {@see RemoteHasherInterface} against your own server extension.
 */
final class ShellSumRemoteHasher implements RemoteHasherInterface
{
    /**
     * @param string $algorithm Algorithm name passed through to
     *        {@see RemoteHasherInterface::algorithm()}. Defaults to
     *        `sha256` to match `$binary`. Must be a name `hash_file()`
     *        accepts on the LOCAL side too — SftpClient hashes both
     *        ends with the same name and compares.
     * @param string $binary    Server-side binary to invoke
     *        (`sha256sum`, `sha1sum`, `md5sum`, `b3sum`, …). Tied to
     *        `$algorithm` only by convention; mismatching them is the
     *        caller's bug.
     */
    public function __construct(
        public readonly string $algorithm = 'sha256',
        public readonly string $binary = 'sha256sum',
    ) {}

    /** {@inheritDoc} */
    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Exec `$binary <remotePath>` over the existing SSH session and
     * parse the leading hex digest from stdout. Lowercase-hex.
     *
     * @throws TransferException if `ssh2_exec` returned false, the
     *         stream was empty, the output couldn't be parsed, or the
     *         client isn't connected.
     */
    public function hash(SftpClient $client, string $remotePath): string
    {
        $sessionAndExec = self::session($client);
        $session = $sessionAndExec[0];
        $exec = $sessionAndExec[1];

        // escapeshellarg quotes for POSIX sh — covers the spaces / single
        // quotes that show up in real-world filenames. Refuses NUL bytes
        // implicitly via the upstream PathValidator.
        $stream = $exec($session, $this->binary . ' ' . escapeshellarg($remotePath));
        if ($stream === false || ! \is_resource($stream)) {
            throw new TransferException(
                'ShellSumRemoteHasher: ssh2_exec returned false for ' . $this->binary . ' on ' . $remotePath,
            );
        }
        stream_set_blocking($stream, true);
        // stream_get_contents on a successfully-opened, blocking stream
        // doesn't return false in practice; we coerce to '' so the
        // empty-output branch below catches every "ssh2_exec gave us a
        // dud stream" scenario in one place rather than splitting the
        // error handling across two branches.
        $raw = stream_get_contents($stream);
        fclose($stream);
        $line = trim($raw === false ? '' : $raw);
        if ($line === '') {
            throw new TransferException(
                'ShellSumRemoteHasher: empty output from ' . $this->binary . ' for ' . $remotePath
                . ' — binary missing or path unreadable',
            );
        }
        // "<hex>  <path>" or "<hex> <path>" — match the leading hex run.
        if (preg_match('/^([0-9a-fA-F]+)\b/', $line, $m) !== 1) {
            throw new TransferException(
                'ShellSumRemoteHasher: could not parse digest from ' . $this->binary . ' output: ' . $line,
            );
        }

        return strtolower($m[1]);
    }

    /**
     * Pull the session + adapter exec callable out of SftpClient via
     * reflection. Keeping the SftpClient surface narrower (no
     * `getSshSession()` public accessor) than this helper requires is a
     * deliberate trade — exposing the raw SSH session to callers invites
     * exactly the kind of out-of-band ssh2_* call that the rest of the
     * wrapper exists to prevent.
     *
     * @return array{0: mixed, 1: callable(mixed, string): mixed}
     */
    private static function session(SftpClient $client): array
    {
        $ref = new \ReflectionObject($client);

        $sessionProp = $ref->getProperty('sshSession');
        $session = $sessionProp->getValue($client);

        $ssh2Prop = $ref->getProperty('ssh2');
        $ssh2 = $ssh2Prop->getValue($client);

        if ($session === null || ! $ssh2 instanceof Ssh2FunctionsInterface) {
            throw new TransferException(
                'ShellSumRemoteHasher: SftpClient is not connected; call connect() first.',
            );
        }
        $exec = static fn(mixed $s, string $cmd): mixed => $ssh2->exec($s, $cmd);

        return [$session, $exec];
    }
}
