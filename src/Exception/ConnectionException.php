<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Transport-level failure: TCP refused, SSH handshake failure, fingerprint
 * mismatch, SFTP subsystem unavailable, or attempt to use a method before
 * connect() was called.
 */
final class ConnectionException extends SshException {}
