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
 * The interface is stable but unwired — `SftpClient::upload()` /
 * `SftpClient::download()` do not yet invoke listeners. The hook is added
 * by P6 in {@see PRODUCTION_GRADE.md}. Until then, defining an
 * implementation only gives downstream consumers type safety to prepare
 * against.
 *
 * ## Lifecycle
 *
 * Exactly one of `completed()` or `failed()` is called per `started()`.
 * Implementations should treat `failed()` as the cleanup signal regardless of
 * whether the failure was thrown by this listener itself.
 *
 * @phpstan-type Operation 'upload'|'download'|'scpUpload'|'scpDownload'
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
