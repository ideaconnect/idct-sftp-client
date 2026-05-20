<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

/**
 * Resolves SSH credentials per host. Implement this to plug a secret
 * store (Vault, AWS Secrets Manager, GCP Secret Manager, a local
 * keychain, …) into {@see \IDCT\Networking\Ssh\SftpClient} without
 * the client knowing about the source.
 *
 * The client calls {@see load()} once per `connect()` when no
 * explicit `setCredentials()` was used. Implementations MAY cache,
 * but the client treats each call as authoritative — return whatever
 * is correct *right now* for `$host`.
 *
 * The default implementation {@see StaticCredentialsLoader} wraps a
 * single {@see CredentialsInterface} instance and returns it for
 * every host; it exists so callers using `setCredentials()` directly
 * still flow through the same plumbing.
 */
interface CredentialsLoaderInterface
{
    /**
     * @param string $host The host the client is about to connect to;
     *                     loaders may key on it (e.g. one Vault path
     *                     per environment) or ignore it entirely.
     */
    public function load(string $host): CredentialsInterface;
}
