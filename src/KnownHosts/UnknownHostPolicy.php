<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\KnownHosts;

/**
 * What {@see \IDCT\Networking\Ssh\SftpClient::connect()} should do when
 * the server's host key is not present in the configured `known_hosts`
 * file.
 *
 * Mismatch (key present but different from server) is a separate code
 * path and ALWAYS rejects — no policy override. Mismatch is a MITM
 * indicator, not an unknown-host condition.
 */
enum UnknownHostPolicy
{
    /**
     * Refuse the connection. Safest default. Disconnect the underlying
     * session before raising so the peer doesn't see authentication
     * traffic.
     */
    case Reject;

    /**
     * Trust on first use: the new key is appended to the `known_hosts`
     * file (creating it if missing) and the connection proceeds. Suitable
     * for bootstrapping a fresh deployment. NOT a substitute for
     * out-of-band fingerprint verification when the network path can be
     * intercepted.
     *
     * The appended entry uses a non-OpenSSH keytype (`sha256-fpr`) and
     * stores the hex fingerprint rather than the raw key blob, because
     * ext-ssh2 doesn't surface the raw host key — only its fingerprint.
     * OpenSSH itself ignores unknown keytypes when reading the file, so
     * coexistence with `ssh(1)` is safe; the entry is only readable by
     * subsequent runs of this library.
     */
    case TrustOnFirstUse;
}
