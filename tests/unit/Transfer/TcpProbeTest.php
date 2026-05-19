<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Transfer;

use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Transfer\TcpProbe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Two cases: the probe must SUCCEED against a listener we control, and
 * must FAIL fast against a non-listening port (we get one by binding-
 * then-closing — the OS reuses the port number while it's in TIME_WAIT
 * but the listener is gone). Failure path covers the typed
 * ConnectionException and its `host:port within Ns` message shape.
 */
#[CoversClass(TcpProbe::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(ConnectionException::class)]
final class TcpProbeTest extends TestCase
{
    public function testCheckReturnsNormallyWhenPeerAccepts(): void
    {
        // Bind a server on a random port; let TcpProbe::check open and
        // immediately close a connection to it.
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($server, "could not bind test server: {$errstr} ({$errno})");
        try {
            $addr = stream_socket_get_name($server, false);
            self::assertIsString($addr);
            [$host, $portStr] = explode(':', $addr);
            $port = (int) $portStr;

            // The probe shouldn't throw — successful TCP connect, close,
            // return void.
            TcpProbe::check($host, $port, 2);

            // Accept-and-close the dangling client socket so the test
            // doesn't leave a half-open connection behind. Use a non-
            // blocking timeout so we don't hang if PHP's event loop
            // hasn't surfaced the accept yet.
            $client = @stream_socket_accept($server, 1);
            if ($client !== false) {
                fclose($client);
            }
        } finally {
            fclose($server);
        }
    }

    public function testCheckThrowsConnectionExceptionWhenPortHasNoListener(): void
    {
        // Bind-then-close gives us a port number that's recently been
        // bound; the OS reports "connection refused" on connect when no
        // listener is present, which is exactly the failure mode the
        // probe exists to surface fast.
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($server);
        $addr = stream_socket_get_name($server, false);
        self::assertIsString($addr);
        [$host, $portStr] = explode(':', $addr);
        $port = (int) $portStr;
        fclose($server);

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessageMatches(
            sprintf('/TCP probe to %s:%d failed within 1s/', preg_quote($host, '/'), $port),
        );
        TcpProbe::check($host, $port, 1);
    }
}
