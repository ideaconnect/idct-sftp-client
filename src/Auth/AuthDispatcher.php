<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;

/**
 * Dispatches `CredentialsInterface` against the ext-ssh2 auth functions.
 *
 * Lives in the {@see \IDCT\Networking\Ssh\Auth} domain so a custom
 * credentials backend (Vault / Secrets Manager / GCP / etc.) can be
 * implemented against `CredentialsInterface` without the consumer
 * having to load ext-ssh2. The dispatcher itself is the one place
 * that bridges "abstract credentials" → "ssh2_auth_* call".
 *
 * The dispatcher does NOT:
 *  - call `AuthFailureRateLimiter` (the caller wires it around
 *    `dispatch()` so the limiter can also fire on connect-time
 *    failure paths that don't reach the dispatcher);
 *  - log (logging stays on `SftpClient` to keep the lint-enforced
 *    redaction rule in one place);
 *  - throw on rejection (returns `false` instead — `SftpClient`
 *    formats the `AuthenticationException` with host/port context).
 */
final class AuthDispatcher
{
    /**
     * Run the auth leg matching `$credentials->getMode()`. Returns
     * `true` on success, `false` on rejection. Each ssh2_auth_* call
     * is funnelled through the adapter so the boundary `@`-suppression
     * lives in one place (see `Ssh2Functions` docblock).
     *
     * @param resource $session
     */
    public static function dispatch(
        mixed $session,
        CredentialsInterface $credentials,
        Ssh2FunctionsInterface $ssh2,
    ): bool {
        return match ($credentials->getMode()) {
            AuthMode::None => $ssh2->authNone($session, $credentials->getUsername()),
            AuthMode::Password => $ssh2->authPassword(
                $session,
                $credentials->getUsername(),
                (string) $credentials->getPassword(),
            ),
            AuthMode::PublicKey => $ssh2->authPublicKey(
                $session,
                $credentials->getUsername(),
                (string) $credentials->getPublicKey(),
                (string) $credentials->getPrivateKey(),
                $credentials->getPassphrase(),
            ),
            AuthMode::Both => self::dispatchBoth($session, $credentials, $ssh2),
        };
    }

    /**
     * Multi-factor: pubkey AND password must both succeed. Servers
     * configured with `AuthenticationMethods publickey,password` accept
     * only both legs; servers requiring either accept a single leg, so
     * `Both` mode is the conservative choice when the policy is unknown.
     *
     * @param resource $session
     */
    private static function dispatchBoth(
        mixed $session,
        CredentialsInterface $credentials,
        Ssh2FunctionsInterface $ssh2,
    ): bool {
        $pubkeyOk = $ssh2->authPublicKey(
            $session,
            $credentials->getUsername(),
            (string) $credentials->getPublicKey(),
            (string) $credentials->getPrivateKey(),
            $credentials->getPassphrase(),
        );

        $passwordOk = $ssh2->authPassword(
            $session,
            $credentials->getUsername(),
            (string) $credentials->getPassword(),
        );

        return $pubkeyOk && $passwordOk;
    }
}
