<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\HostKey;

/**
 * Hash algorithm to use when computing/comparing the server host-key fingerprint.
 * Integer values mirror ext-ssh2's SSH2_FINGERPRINT_* flag bits.
 */
enum FingerprintAlgorithm: int
{
    /**
     * MD5 — historical default for `ssh-keygen -l`. Don't pin against
     * MD5 fingerprints in new code; preimage attacks are practical.
     * Included for compatibility with older systems / log archives.
     */
    case Md5 = 0;

    /**
     * SHA-1 — what older libssh2 builds (< 1.9) support natively. Not
     * collision-resistant in general, but for fingerprint comparison
     * against a single specific key blob it's still safe in practice.
     * The known-hosts module ({@see \IDCT\Networking\Ssh\KnownHosts\KnownHostsFile})
     * uses SHA-1 internally for that reason.
     */
    case Sha1 = 1;

    /**
     * SHA-256 — recommended for new pinning. Requires libssh2 ≥ 1.9
     * (the `SSH2_FINGERPRINT_SHA256` constant is not defined in older
     * builds). When unavailable, `ssh2_fingerprint` silently falls
     * back to MD5, so verify your libssh2 version before using this.
     */
    case Sha256 = 2;
}
