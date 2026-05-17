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
     * Use the named factories; the constructor is internal to this class.
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

    public static function withPassword(
        string $username,
        #[SensitiveParameter]
        string $password,
    ): self {
        return new self(AuthMode::Password, $username, password: $password);
    }

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

    public static function withNone(string $username): self
    {
        return new self(AuthMode::None, $username);
    }

    public function getMode(): AuthMode
    {
        return $this->mode;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    /**
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
