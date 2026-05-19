<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

/**
 * Authentication strategy the SFTP client should use when handshaking.
 *
 * The integer backing keeps wire compatibility with the pre-1.0 class
 * constants (`AuthMode::PASSWORD == 1`, etc.) for callers that
 * persisted the int value to storage.
 *
 * `SftpClient::authorize()` matches on the enum case and dispatches to
 * the right `ssh2_auth_*` call. {@see needsPassword()} and
 * {@see needsKeys()} are convenience predicates used by
 * {@see Credentials} to validate that the caller supplied the right
 * fields for the chosen mode.
 */
enum AuthMode: int
{
    /**
     * Anonymous authentication (`ssh2_auth_none`). The server still
     * gets the username so its policy can grant or refuse access.
     */
    case None = 0;

    /** Password authentication (`ssh2_auth_password`). */
    case Password = 1;

    /** Public-key authentication (`ssh2_auth_pubkey_file`). */
    case PublicKey = 2;

    /**
     * Multi-factor: both the public-key leg AND the password leg must
     * succeed. Matches an OpenSSH `AuthenticationMethods publickey,password`
     * policy.
     */
    case Both = 3;

    /**
     * True when the mode requires a non-empty password (Password / Both).
     * Used by Credentials' constructor validation.
     */
    public function needsPassword(): bool
    {
        return $this === self::Password || $this === self::Both;
    }

    /**
     * True when the mode requires public- and private-key file paths
     * (PublicKey / Both). Used by Credentials' constructor validation.
     */
    public function needsKeys(): bool
    {
        return $this === self::PublicKey || $this === self::Both;
    }
}
