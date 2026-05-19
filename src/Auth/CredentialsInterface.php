<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

/**
 * Pure data interface for SSH credentials.
 *
 * Implementations expose the data fields the client needs to perform the
 * authentication step the chosen mode demands. The interface intentionally
 * carries no behaviour: the auth-dispatch logic lives in {@see SftpClient}.
 *
 * Implementors that wrap external secret stores (Vault, AWS Secrets Manager,
 * GCP Secret Manager) can read on demand inside their getters; the client
 * calls each getter at most once per connect attempt.
 *
 * ## Sensitive-value handling responsibility
 *
 * `getPassword()` and `getPassphrase()` MAY return secrets. Implementations
 * are responsible for:
 * - applying `#[\SensitiveParameter]` on any *constructor* parameters that
 *   accept these values, so they redact from stack traces;
 * - implementing `__debugInfo()` (or equivalent) to redact stored values
 *   from `var_dump` / `print_r` / serializer output.
 *
 * The standard implementation `Credentials` does both.
 */
interface CredentialsInterface
{
    /**
     * Which authentication leg the client should run on `connect()`.
     * Drives the match in `SftpClient::authorize()`.
     */
    public function getMode(): AuthMode;

    /** SSH login username — required regardless of mode. */
    public function getUsername(): string;

    /**
     * Plain-text password, or null when the mode doesn't use one.
     * MUST be non-null when {@see getMode()} is `Password` or `Both`.
     */
    public function getPassword(): ?string;

    /**
     * Absolute path to the public-key file (OpenSSH format), or null
     * for modes that don't use a key. MUST be non-null when the mode
     * is `PublicKey` or `Both`.
     */
    public function getPublicKey(): ?string;

    /**
     * Absolute path to the matching private-key file, or null. Same
     * "MUST be present for key-based modes" rule as
     * {@see getPublicKey()}.
     */
    public function getPrivateKey(): ?string;

    /**
     * Passphrase decrypting the private key, or null if the key has
     * no passphrase (or the mode doesn't use keys).
     */
    public function getPassphrase(): ?string;
}
