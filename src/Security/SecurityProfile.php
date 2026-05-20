<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Security;

/**
 * Curated cipher / MAC / KEX / host-key allow-list for
 * {@see \IDCT\Networking\Ssh\SftpClient::connect()}.
 *
 * The plan called for three named presets (Modern / Compatible /
 * Legacy). Each maps to the `$methods` array libssh2 accepts via
 * `ssh2_connect`. Picking a profile is a one-liner; the lists below
 * are the substance of the choice.
 *
 * ## Modern
 *
 * Only post-2014 algorithms with no known weakness, no CBC modes, no
 * SHA-1 (KEX/MAC), no RSA SHA-1 host keys. Tight enough to reject any
 * server that hasn't rolled algorithm support in the last decade.
 *
 * ## Compatible
 *
 * Returns `null` — `SftpClient::connect()` then passes no `$methods`
 * argument to `ssh2_connect`, so the libssh2 default negotiation
 * applies. This is the safe default for general-purpose use.
 *
 * ## Legacy
 *
 * Permissive list including SHA-1 MACs, CBC modes, and DH group14 for
 * KEX. Useful for reaching old appliances; the wrapper logs a
 * `notice`-level record whenever this profile is used so the
 * compromise is auditable in production logs.
 *
 * ## Why hard-coded lists rather than a builder
 *
 * The point of the enum is *named presets* — three sensible defaults
 * the caller doesn't have to research. Callers who need bespoke
 * algorithm selection should pass `?array $methods` directly to
 * `SftpClient::connect()` (the underlying adapter already supports
 * it) and ignore the enum entirely.
 *
 * @phpstan-import-type Ssh2Methods from \IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface
 */
enum SecurityProfile
{
    /**
     * Locked to post-2014 algorithms: curve25519 KEX, Ed25519 host
     * keys, ChaCha20-Poly1305 + AES-GCM ciphers, SHA-256/512-ETM MACs.
     * Rejects servers that haven't rolled algorithm support in the
     * last decade.
     */
    case Modern;

    /**
     * Returns `null` from {@see toMethodsArray()` so the caller passes
     * no `$methods` argument to `ssh2_connect` and the libssh2 stock
     * negotiation applies. The safe default for general-purpose use.
     */
    case Compatible;

    /**
     * Permissive list including SHA-1 MACs, CBC modes, and DH group14.
     * Useful for reaching old appliances; the client logs a
     * `notice`-level record whenever this profile is in use so the
     * compromise is auditable in production logs.
     */
    case Legacy;

    /**
     * Convert the profile to the `$methods` shape `ssh2_connect`
     * expects. Returns `null` for {@see self::Compatible} so the
     * caller passes nothing to libssh2 and gets the stock negotiation.
     *
     * @return Ssh2Methods|null
     */
    public function toMethodsArray(): ?array
    {
        return match ($this) {
            self::Modern => [
                // Post-2014 KEX only; no SHA-1, no NIST P-curves.
                'kex' => 'curve25519-sha256,curve25519-sha256@libssh.org',
                // Ed25519 host key only — RSA host keys default to SHA-1
                // signatures on older libssh2 builds and we want to
                // reject those outright.
                'hostkey' => 'ssh-ed25519',
                'client_to_server' => [
                    'crypt' => 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
                    'mac' => 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com',
                ],
                'server_to_client' => [
                    'crypt' => 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com',
                    'mac' => 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com',
                ],
            ],
            self::Compatible => null,
            self::Legacy => [
                'kex' => 'curve25519-sha256,curve25519-sha256@libssh.org,'
                    . 'diffie-hellman-group14-sha256,diffie-hellman-group14-sha1',
                'hostkey' => 'ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384',
                'client_to_server' => [
                    'crypt' => 'chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc',
                    'mac' => 'hmac-sha2-256,hmac-sha2-512,hmac-sha1',
                ],
                'server_to_client' => [
                    'crypt' => 'chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc',
                    'mac' => 'hmac-sha2-256,hmac-sha2-512,hmac-sha1',
                ],
            ],
        };
    }
}
