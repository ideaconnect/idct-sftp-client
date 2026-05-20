<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\HostKey;

/**
 * Output encoding for the host-key fingerprint string.
 * Integer values mirror ext-ssh2's SSH2_FINGERPRINT_HEX / SSH2_FINGERPRINT_RAW.
 */
enum FingerprintEncoding: int
{
    /**
     * Lowercase hex string with no separators, e.g. `"abcdef0123…"`.
     * The format `expectedFingerprint` is normally compared against.
     */
    case Hex = 0;

    /**
     * Raw binary digest. Same bytes you'd get from `hash($algo, $blob, true)`.
     * Useful only when feeding the digest into another binary protocol;
     * for human / config-file use, prefer {@see self::Hex}.
     */
    case Raw = 2;
}
