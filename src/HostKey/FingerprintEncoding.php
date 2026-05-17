<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\HostKey;

/**
 * Output encoding for the host-key fingerprint string.
 * Integer values mirror ext-ssh2's SSH2_FINGERPRINT_HEX / SSH2_FINGERPRINT_RAW.
 */
enum FingerprintEncoding: int
{
    case Hex = 0;
    case Raw = 2;
}
