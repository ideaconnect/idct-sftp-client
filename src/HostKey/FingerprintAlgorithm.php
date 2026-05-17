<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\HostKey;

/**
 * Hash algorithm to use when computing/comparing the server host-key fingerprint.
 * Integer values mirror ext-ssh2's SSH2_FINGERPRINT_* flag bits.
 */
enum FingerprintAlgorithm: int
{
    case Md5 = 0;
    case Sha1 = 1;
    case Sha256 = 2;
}
