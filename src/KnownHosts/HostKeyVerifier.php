<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\KnownHosts;

use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;

/**
 * Stateless OpenSSH `known_hosts` verifier.
 *
 * `SftpClient::connect()` delegates here once the optional
 * `knownHostsFile` argument is set. The verifier:
 *
 *  1. Reads the server's SHA-1 fingerprint from the live SSH session
 *     (SHA-1 because `SSH2_FINGERPRINT_SHA256` is libssh2 ≥ 1.9 and
 *     this library's floor is older — see `KnownHostsFile` "Why
 *     SHA-1" docblock).
 *  2. Looks the host up in the file via
 *     {@see KnownHostsFile::verifyHost()}.
 *  3. On `Trusted`: returns a {@see HostKeyVerification} carrying the
 *     fingerprint so the caller can log it.
 *  4. On `NoEntries` + {@see UnknownHostPolicy::TrustOnFirstUse}:
 *     appends a fresh entry and returns a verification flagged
 *     `tofuAppended: true`.
 *  5. On `Mismatch`, `NoEntries` + `Reject`, or an unreadable
 *     fingerprint: throws {@see ConnectionException}. The verifier
 *     does NOT call `disconnect()` — session cleanup is the caller's
 *     responsibility (only the caller knows whether retries / lazy
 *     reconnects should preserve or tear down the resource).
 *
 * Logging is also the caller's responsibility. The verifier returns
 * structured data (or throws); `SftpClient` decides log level and
 * context. Keeps secret-redaction enforcement in one place.
 */
final class HostKeyVerifier
{
    /**
     * @param resource $session
     *
     * @throws ConnectionException for any failure mode listed above.
     */
    public static function verify(
        mixed $session,
        string $host,
        int $port,
        string $knownHostsFile,
        UnknownHostPolicy $onUnknownHost,
        Ssh2FunctionsInterface $ssh2,
    ): HostKeyVerification {
        // Hard-coded SHA-1 + HEX (= 1 | 0 = 1). libssh2 < 1.9 doesn't
        // ship the SHA-256 fingerprint constant; we ship against the
        // older floor. See KnownHostsFile's "Why SHA-1" docblock.
        $fp = $ssh2->fingerprint($session, 1);
        if ($fp === false) {
            throw new ConnectionException(\sprintf(
                'Could not read host key fingerprint for %s:%d.',
                $host,
                $port,
            ));
        }

        $hostsFile = new KnownHostsFile($knownHostsFile);
        $decision = $hostsFile->verifyHost($host, $port, $fp);

        if ($decision === HostKeyDecision::Mismatch) {
            throw new ConnectionException(\sprintf(
                'Known-hosts mismatch for %s:%d. The server presented a key (%s) that '
                . 'does not match any entry for this host in %s. Refusing connection.',
                $host,
                $port,
                $fp,
                $knownHostsFile,
            ));
        }

        if ($decision === HostKeyDecision::NoEntries) {
            if ($onUnknownHost === UnknownHostPolicy::Reject) {
                throw new ConnectionException(\sprintf(
                    'Unknown host %s:%d (fingerprint %s) not present in %s. Pass '
                    . 'UnknownHostPolicy::TrustOnFirstUse to accept new hosts.',
                    $host,
                    $port,
                    $fp,
                    $knownHostsFile,
                ));
            }
            $hostsFile->appendFingerprint($host, $port, $fp);

            return new HostKeyVerification($fp, tofuAppended: true);
        }

        return new HostKeyVerification($fp, tofuAppended: false);
    }
}
