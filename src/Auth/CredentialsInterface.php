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
    public function getMode(): AuthMode;

    public function getUsername(): string;

    public function getPassword(): ?string;

    public function getPublicKey(): ?string;

    public function getPrivateKey(): ?string;

    public function getPassphrase(): ?string;
}
