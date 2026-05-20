<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Progress;

/**
 * Receives byte-by-byte progress updates during long-running transfers.
 *
 * Typical implementations: a Symfony `ProgressBar` adapter, a metrics emitter
 * (StatsD / OpenTelemetry), an idle-detector that aborts transfers that have
 * made no progress in N seconds, a structured logger.
 *
 * ## Wiring status
 *
 * Wired by `SftpClient::upload()` / `download()` / `resumeUpload()` /
 * `resumeDownload()` / `uploadStream()` / `downloadStream()`. SCP
 * transfers (`scpUpload()` / `scpDownload()`) do NOT emit progress events
 * — ext-ssh2 doesn't expose libssh2's per-chunk callbacks for `scp_send`
 * / `scp_recv`, and a single `started → completed` pair without any
 * intermediates would mislead callers more than it would help.
 *
 * ## Lifecycle
 *
 * Exactly one of `completed()` or `failed()` is called per `started()`.
 * Implementations should treat `failed()` as the cleanup signal regardless of
 * whether the failure was thrown by this listener itself.
 *
 * @phpstan-type Operation 'upload'|'download'|'resumeUpload'|'resumeDownload'|'uploadStream'|'downloadStream'
 */
interface ProgressListenerInterface
{
    /**
     * @param Operation $operation Which kind of transfer is starting
     * @param int<0, max>|null $totalBytes Size if known; null for streaming sources with unknown length
     */
    public function started(string $operation, ?int $totalBytes): void;

    /**
     * Called repeatedly during the transfer. Frequency is bounded by the
     * configured chunk size (default 1 MiB), so listeners shouldn't perform
     * heavy work here without throttling.
     *
     * @param int<0, max> $bytesDone Cumulative bytes transferred so far
     */
    public function progress(int $bytesDone): void;

    /**
     * @param int<0, max> $bytesDone Final byte count (== $totalBytes when known)
     */
    public function completed(int $bytesDone): void;

    public function failed(\Throwable $e): void;
}
