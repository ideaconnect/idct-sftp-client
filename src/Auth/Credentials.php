<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

use IDCT\Networking\Ssh\Exception\ConfigurationException;
use SensitiveParameter;

/**
 * Default {@see CredentialsInterface} implementation: an immutable value
 * object constructed via named factories.
 *
 * Sensitive fields (password, passphrase) are marked `#[\SensitiveParameter]`
 * on constructor / factory parameters (redacted from stack traces) and
 * masked in `__debugInfo()` output.
 *
 * Properties remain `public readonly` for backwards compatibility with 1.0
 * direct-access callers; the getters defined by {@see CredentialsInterface}
 * forward to them.
 */
final class Credentials implements CredentialsInterface
{
    /**
     * Use the named factories — the constructor is private so an
     * AuthMode-incompatible field combination can't be constructed
     * from outside this class.
     *
     * @param AuthMode    $mode       Which auth strategy is in play.
     * @param string      $username   SSH login; rejected if empty.
     * @param string|null $password   Plain-text password; required for `Password` / `Both`.
     * @param string|null $publicKey  Absolute path to the public-key file; required for `PublicKey` / `Both`.
     * @param string|null $privateKey Absolute path to the matching private key; required when $publicKey is.
     * @param string|null $passphrase Optional passphrase decrypting $privateKey.
     *
     * @throws ConfigurationException empty username, or a key-based mode
     *         pointing at a file that doesn't exist on the local FS.
     */
    private function __construct(
        public readonly AuthMode $mode,
        public readonly string $username,
        #[SensitiveParameter]
        public readonly ?string $password = null,
        public readonly ?string $publicKey = null,
        public readonly ?string $privateKey = null,
        #[SensitiveParameter]
        public readonly ?string $passphrase = null,
    ) {
        if ($username === '') {
            throw new ConfigurationException('Username must be at least 1 character long.');
        }

        // password/publicKey/privateKey nullability is already enforced by the
        // named factories — the constructor is private so untyped construction
        // can't reach here.
        if ($mode->needsKeys()) {
            if (! file_exists((string) $publicKey)) {
                throw new ConfigurationException('Public key file does not exist: ' . $publicKey);
            }
            if (! file_exists((string) $privateKey)) {
                throw new ConfigurationException('Private key file does not exist: ' . $privateKey);
            }
        }
    }

    /**
     * Factory for password authentication.
     *
     * @throws ConfigurationException on empty username.
     */
    public static function withPassword(
        string $username,
        #[SensitiveParameter]
        string $password,
    ): self {
        return new self(AuthMode::Password, $username, password: $password);
    }

    /**
     * Factory for public-key authentication.
     *
     * @param string      $publicKey  Absolute path to the public key file (OpenSSH `id_rsa.pub` format).
     * @param string      $privateKey Absolute path to the matching private key.
     * @param string|null $passphrase Optional passphrase for the private key.
     *
     * @throws ConfigurationException on empty username or missing key files.
     */
    public static function withPublicKey(
        string $username,
        string $publicKey,
        string $privateKey,
        #[SensitiveParameter]
        ?string $passphrase = null,
    ): self {
        return new self(
            AuthMode::PublicKey,
            $username,
            publicKey: $publicKey,
            privateKey: $privateKey,
            passphrase: $passphrase,
        );
    }

    /**
     * Factory for multi-factor (publickey + password) authentication.
     * Both legs must succeed for the connect to be accepted.
     *
     * @throws ConfigurationException on empty username or missing key files.
     */
    public static function withBoth(
        string $username,
        #[SensitiveParameter]
        string $password,
        string $publicKey,
        string $privateKey,
        #[SensitiveParameter]
        ?string $passphrase = null,
    ): self {
        return new self(
            AuthMode::Both,
            $username,
            password: $password,
            publicKey: $publicKey,
            privateKey: $privateKey,
            passphrase: $passphrase,
        );
    }

    /**
     * Factory for anonymous authentication (`ssh2_auth_none`). Sends
     * the username only; the server's policy decides whether to grant
     * access without proof.
     *
     * @throws ConfigurationException on empty username.
     */
    public static function withNone(string $username): self
    {
        return new self(AuthMode::None, $username);
    }

    /** {@inheritDoc} */
    public function getMode(): AuthMode
    {
        return $this->mode;
    }

    /** {@inheritDoc} */
    public function getUsername(): string
    {
        return $this->username;
    }

    /** {@inheritDoc} */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /** {@inheritDoc} */
    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    /** {@inheritDoc} */
    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    /** {@inheritDoc} */
    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    /**
     * Sensitive-value redaction for `var_dump` / `print_r` / `error_log`
     * output. Password and passphrase are masked when present (so the
     * mask itself signals "yes, there's a secret here" without
     * leaking the value).
     *
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return [
            'mode' => $this->mode->name,
            'username' => $this->username,
            'password' => $this->password === null ? null : '***REDACTED***',
            'publicKey' => $this->publicKey,
            'privateKey' => $this->privateKey,
            'passphrase' => $this->passphrase === null ? null : '***REDACTED***',
        ];
    }
}
