<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Authentication rejected (wrong password, bad key, server policy refusal).
 * Distinct from {@see ConnectionException} — the TCP / SSH handshake
 * succeeded; the user identity didn't.
 */
final class AuthenticationException extends SshException {}
