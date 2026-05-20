<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Transfer;

use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;

/**
 * Stateless helpers for moving bytes between PHP stream resources.
 *
 * Lives here so {@see \IDCT\Networking\Ssh\SftpClient} can stay focused
 * on lifecycle / dispatch and the bulk-copy logic — chunked fread/fwrite,
 * partial-path naming, defensive seek — is testable in isolation.
 *
 * Every method is `static`; no shared state. The collaborator does not
 * log or emit events of its own. The client decides what to log around
 * each call (kept in one place to honour the redaction rules enforced
 * by `tests/unit/LoggerRedactionLintTest.php`).
 */
final class StreamCopier
{
    /**
     * Chunked copy from `$from` to `$to`. Emits `progress($cumulativeBytes)`
     * after every successful chunk write. Does **not** call `started()` /
     * `completed()` / `failed()` — the lifecycle terminator depends on
     * whether the whole operation (size verification, rename, checksum,
     * …) succeeds, and only the caller knows.
     *
     * Avoids `feof()` because some libssh2 stream wrappers return true on
     * EOF incorrectly; `fread === ''` is the reliable signal.
     *
     * @param resource $from
     * @param resource $to
     * @param int<1, max> $chunkSize Bytes per `fread` / `fwrite`. Pass
     *        the client's configured chunk size; 0/negative values would
     *        either spin or error and are excluded by the type bound.
     * @return int<0, max> total bytes copied
     *
     * @throws TransferException on any fread/fwrite failure (with the
     *         caller-supplied `$failureMessage` as the exception text).
     */
    public static function copy(
        mixed $from,
        mixed $to,
        int $chunkSize,
        ?ProgressListenerInterface $progress,
        string $failureMessage,
    ): int {
        $copied = 0;
        while (true) {
            $buf = @fread($from, $chunkSize);
            if ($buf === false) {
                throw new TransferException($failureMessage);
            }
            if ($buf === '') {
                return $copied;
            }
            $written = @fwrite($to, $buf);
            $bufLen = \strlen($buf);
            if ($written === false || $written < $bufLen) {
                throw new TransferException($failureMessage);
            }
            $copied += $written;
            $progress?->progress($copied);
        }
    }

    /**
     * Defensive seek helper used by both resume paths. Regular-file streams
     * always seek successfully, so this branch only fires for pathological
     * stream wrappers (non-seekable sources). Without it, a returned `-1`
     * silently leaves the read cursor at zero and corrupts the resumed
     * transfer — much worse than a clean throw.
     *
     * @param resource $stream
     *
     * @throws TransferException when `fseek` returned non-zero.
     */
    public static function seekOrThrow(mixed $stream, int $offset, string $contextLabel, string $path): void
    {
        if (@fseek($stream, $offset) !== 0) {
            throw new TransferException(\sprintf(
                'Could not seek %s to offset %d: %s',
                $contextLabel,
                $offset,
                $path,
            ));
        }
    }

    /**
     * Build a hidden-dotfile sibling path for partial uploads.
     *
     * Examples (suffix = "partial-abc12345"):
     *  - `/in/report.csv`  → `/in/.report.csv.partial-abc12345`
     *  - `/report.csv`     → `/.report.csv.partial-abc12345`
     *  - `report.csv`      → `.report.csv.partial-abc12345`
     */
    public static function partialPath(string $remote, string $suffix): string
    {
        $base = basename($remote);
        $dir = \dirname($remote);
        $partial = '.' . $base . '.' . $suffix;
        if ($dir === '.' || $dir === '') {
            return $partial;
        }

        return rtrim($dir, '/') . '/' . $partial;
    }
}
