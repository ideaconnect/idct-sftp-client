<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\KnownHosts;

/**
 * Outcome of comparing a server fingerprint against a `known_hosts` file.
 *
 * `Mismatch` means the host appears in the file but with a different
 * fingerprint — a strong MITM indicator. `NoEntries` means no entries
 * match the host at all (this is the bootstrapping / unknown-host case).
 * `Trusted` means a matching entry was found.
 */
enum HostKeyDecision
{
    /** A matching entry was found: server key equals stored fingerprint. */
    case Trusted;

    /**
     * No entries in the file cover this host:port. Bootstrap / unknown
     * host. Action depends on the configured {@see UnknownHostPolicy}.
     */
    case NoEntries;

    /**
     * Host appears in the file but with a different fingerprint. Strong
     * MITM indicator — `SftpClient` always rejects, regardless of policy.
     */
    case Mismatch;
}
