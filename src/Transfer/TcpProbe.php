<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Transfer;

use IDCT\Networking\Ssh\Exception\ConnectionException;

/**
 * Stateless pre-connect TCP reachability probe.
 *
 * `SftpClient::connect()` calls this BEFORE handing the socket to libssh2
 * when the caller supplied a `$timeoutSeconds` argument. A dead host
 * (port firewalled, server down, route black-holed) returns from
 * `stream_socket_client()` with a typed error much faster than libssh2's
 * banner-exchange timeout would — which can otherwise hang the whole
 * worker on `default_socket_timeout`.
 *
 * The probe opens a plain TCP socket and closes it immediately; no
 * SSH bytes are exchanged. Used purely for "is this peer answering?".
 */
final class TcpProbe
{
    /**
     * @throws ConnectionException when the socket can't be opened
     *         within `$timeoutSeconds`.
     */
    public static function check(string $host, int $port, int $timeoutSeconds): void
    {
        $errno = 0;
        $errstr = '';
        $probe = @stream_socket_client(
            \sprintf('tcp://%s:%d', $host, $port),
            $errno,
            $errstr,
            (float) $timeoutSeconds,
        );
        if ($probe === false) {
            throw new ConnectionException(\sprintf(
                'TCP probe to %s:%d failed within %ds: %s (%d).',
                $host,
                $port,
                $timeoutSeconds,
                $errstr,
                $errno,
            ));
        }
        fclose($probe);
    }
}
