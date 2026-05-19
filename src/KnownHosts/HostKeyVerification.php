<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\KnownHosts;

/**
 * Successful outcome of {@see HostKeyVerifier::verify()}.
 *
 * Carries the server's fingerprint so the caller can include it in
 * log records, plus a flag indicating whether the entry was newly
 * appended via TOFU (so the caller can pick an `info`-vs-`debug`
 * log level for the two cases).
 *
 * Failure cases (unreadable fingerprint, mismatch, unknown-host
 * under Reject policy) are signalled by a thrown
 * {@see \IDCT\Networking\Ssh\Exception\ConnectionException}, not by
 * this value — there is no "rejected" instance.
 */
final readonly class HostKeyVerification
{
    public function __construct(
        public string $fingerprint,
        public bool $tofuAppended,
    ) {}
}
