<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\CredentialsInterface;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\EntryType;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\Path\PathValidator;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;
use IDCT\Networking\Ssh\Ssh2\Ssh2Functions;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

final class SftpClient implements SftpClientInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    private ?CredentialsInterface $credentials = null;

    /** @var resource|null */
    private mixed $sshSession = null;

    /** @var resource|null */
    private mixed $sftp = null;

    private string $localPrefix = '';

    private string $remotePrefix = '';

    private bool $fileSizeVerificationEnabled;

    /**
     * When true (default), {@see upload()} writes to a hidden `.partial-{uuid}`
     * sibling first, then renames to the final path — see {@see partialPath()}
     * and {@see doUpload()}. Servers that reject overwrite-on-rename can flip
     * this off via {@see disableAtomicUploads()}; SCP transfers are never
     * atomic (no temp+rename possible) regardless of this flag.
     */
    private bool $atomicUploads;

    /**
     * Bytes per fread/fwrite call inside {@see copyWithProgress()}. 1 MiB
     * is a safe default — some networks are dramatically faster with 8 MiB
     * but the floor below which transfers visibly stutter is around 64 KiB.
     * Adjust via {@see setChunkSize()}.
     *
     * Constrained to int<1, max> via the constructor + setter — fread()
     * requires a positive length, and the validation throws on smaller.
     *
     * @var int<1, max>
     */
    private int $chunkSize;

    /** Default chunk size if the caller doesn't override (1 MiB). */
    public const DEFAULT_CHUNK_SIZE = 1 << 20;

    private readonly Ssh2FunctionsInterface $ssh2;

    /**
     * Per-connection identifier used in every log record so downstream
     * aggregation can group operations by session. Reset on each connect(),
     * cleared on close().
     */
    private ?string $correlationId = null;

    /** Host of the currently-established session; null when disconnected. */
    private ?string $host = null;

    /** Port of the currently-established session; null when disconnected. */
    private ?int $port = null;

    // ── stored connect arguments, used by lazy reconnect on retry ─────────
    private ?int $timeoutSeconds = null;

    private ?string $expectedFingerprint = null;

    private FingerprintAlgorithm $fingerprintAlgorithm = FingerprintAlgorithm::Sha256;

    private FingerprintEncoding $fingerprintEncoding = FingerprintEncoding::Hex;

    private RetryPolicyInterface $retryPolicy;

    /**
     * Caller-supplied static context merged into every log record (e.g.
     * request_id, tenant_id). Set via {@see setLogContext()}.
     *
     * @var array<string, mixed>
     */
    private array $logContext = [];

    public function __construct(
        bool $enableFileSizeVerification = false,
        ?Ssh2FunctionsInterface $ssh2 = null,
        ?RetryPolicyInterface $retryPolicy = null,
        bool $atomicUploads = true,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
    ) {
        if ($chunkSize < 1) {
            throw new ConfigurationException(\sprintf('chunkSize must be >= 1; got %d.', $chunkSize));
        }
        $this->fileSizeVerificationEnabled = $enableFileSizeVerification;
        $this->ssh2 = $ssh2 ?? new Ssh2Functions();
        $this->retryPolicy = $retryPolicy ?? new ExponentialBackoffRetryPolicy();
        $this->atomicUploads = $atomicUploads;
        $this->chunkSize = $chunkSize;
        $this->logger = new NullLogger();
    }

    public function setRetryPolicy(RetryPolicyInterface $policy): self
    {
        $this->retryPolicy = $policy;

        return $this;
    }

    public function getRetryPolicy(): RetryPolicyInterface
    {
        return $this->retryPolicy;
    }

    /**
     * Replace the caller-side static log context. The keys correlation_id,
     * host, and port are reserved; entries with those keys are stripped and
     * will be overwritten by the client itself.
     *
     * @param array<string, mixed> $context
     */
    public function setLogContext(array $context): self
    {
        unset($context['correlation_id'], $context['host'], $context['port']);
        $this->logContext = $context;

        return $this;
    }

    public function __destruct()
    {
        $this->close();
    }

    public function enableFileSizeVerification(): self
    {
        $this->fileSizeVerificationEnabled = true;

        return $this;
    }

    public function disableFileSizeVerification(): self
    {
        $this->fileSizeVerificationEnabled = false;

        return $this;
    }

    public function enableAtomicUploads(): self
    {
        $this->atomicUploads = true;

        return $this;
    }

    public function disableAtomicUploads(): self
    {
        $this->atomicUploads = false;

        return $this;
    }

    public function getAtomicUploads(): bool
    {
        return $this->atomicUploads;
    }

    public function setChunkSize(int $bytes): self
    {
        if ($bytes < 1) {
            throw new ConfigurationException(\sprintf('chunkSize must be >= 1; got %d.', $bytes));
        }
        $this->chunkSize = $bytes;

        return $this;
    }

    public function getChunkSize(): int
    {
        return $this->chunkSize;
    }

    public function setCredentials(CredentialsInterface $credentials): self
    {
        $this->credentials = $credentials;

        return $this;
    }

    public function getCredentials(): ?CredentialsInterface
    {
        return $this->credentials;
    }

    public function setLocalPrefix(string $prefix): self
    {
        $this->localPrefix = $prefix;

        return $this;
    }

    public function getLocalPrefix(): string
    {
        return $this->localPrefix;
    }

    public function setRemotePrefix(string $prefix): self
    {
        $this->remotePrefix = $prefix;

        return $this;
    }

    public function getRemotePrefix(): string
    {
        return $this->remotePrefix;
    }

    public function connect(
        string $host,
        int $port = 22,
        ?int $timeoutSeconds = null,
        ?string $expectedFingerprint = null,
        FingerprintAlgorithm $fingerprintAlgorithm = FingerprintAlgorithm::Sha256,
        FingerprintEncoding $fingerprintEncoding = FingerprintEncoding::Hex,
    ): self {
        if ($this->credentials === null) {
            throw new ConfigurationException('Credentials must be set before calling connect().');
        }

        // Open the per-connection log scope ONCE; retries reuse the same id
        // so a single aggregator query sees the whole attempt sequence.
        $this->correlationId = bin2hex(random_bytes(8));
        $this->host = $host;
        $this->port = $port;
        $this->timeoutSeconds = $timeoutSeconds;
        $this->expectedFingerprint = $expectedFingerprint;
        $this->fingerprintAlgorithm = $fingerprintAlgorithm;
        $this->fingerprintEncoding = $fingerprintEncoding;

        $this->log('info', 'SSH connect attempt', ['mode' => $this->credentials->getMode()->name]);

        $this->retry('connect', fn(): true => $this->doConnect());

        return $this;
    }

    /**
     * Actual connect machinery. Reads its inputs from the stored connect-args
     * properties so {@see retry()} can re-run it on lazy reconnect without
     * needing to re-thread arguments.
     *
     * Returns true on success so the closure in {@see connect()} has a value
     * to return; the meaningful side effects are assigning $sshSession +
     * $sftp on the instance.
     */
    private function doConnect(): true
    {
        // Read the connection scope into locals up-front; the public connect()
        // is the only caller and always sets these, but we use defensive
        // throws (rather than assert()) so PHPStan can narrow the types.
        $credentials = $this->credentials;
        $host = $this->host;
        $port = $this->port;
        if ($credentials === null || $host === null || $port === null) {
            throw new ConfigurationException('doConnect() called without a prepared connection scope; this is an internal invariant violation.');
        }

        if ($this->timeoutSeconds !== null) {
            $this->probeTcp($host, $port, $this->timeoutSeconds);
        }

        $session = $this->ssh2->connect($host, $port);
        if ($session === false) {
            $this->log('error', 'SSH connect failed (transport)');

            throw new ConnectionException(\sprintf('Could not connect to %s:%d.', $host, $port));
        }

        if ($this->expectedFingerprint !== null) {
            $actual = $this->ssh2->fingerprint(
                $session,
                $this->fingerprintAlgorithm->value | $this->fingerprintEncoding->value,
            );
            if ($actual === false) {
                $this->ssh2->disconnect($session);
                $this->log('error', 'Host key fingerprint unreadable');

                throw new ConnectionException(\sprintf(
                    'Could not read host key fingerprint for %s:%d.',
                    $host,
                    $port,
                ));
            }
            if (! hash_equals(strtolower($this->expectedFingerprint), strtolower($actual))) {
                $this->ssh2->disconnect($session);
                $this->log('error', 'Host key fingerprint mismatch', [
                    'expected' => $this->expectedFingerprint,
                    'actual' => $actual,
                ]);

                throw new ConnectionException(\sprintf(
                    'Host key fingerprint mismatch for %s:%d (expected %s, got %s).',
                    $host,
                    $port,
                    $this->expectedFingerprint,
                    $actual,
                ));
            }
        }

        $this->authorize($session, $credentials);

        $sftp = $this->ssh2->sftp($session);
        if ($sftp === false) {
            $this->ssh2->disconnect($session);
            $this->log('error', 'SFTP subsystem initialisation failed');

            throw new ConnectionException('Could not initialise SFTP subsystem.');
        }

        $this->sshSession = $session;
        $this->sftp = $sftp;
        $this->log('info', 'SSH connect ok');

        return true;
    }

    public function close(): self
    {
        $session = $this->sshSession;
        if ($session === null) {
            return $this;
        }

        $this->log('debug', 'SSH disconnect');

        $this->sftp = null;
        $this->sshSession = null;

        try {
            $this->ssh2->disconnect($session);
        } catch (\Throwable $e) {
            // Best-effort: the peer may already be gone. Suppressing here is intentional;
            // every other error path in this class surfaces the failure. Log at
            // warning so unexpected disconnects are visible in aggregation.
            $this->log('warning', 'SSH disconnect threw (peer likely already gone)', [
                'exception' => $e::class,
                'reason' => $e->getMessage(),
            ]);
        }

        // Clear the connection-scoped log context AFTER the final disconnect log
        // so the correlation_id is still attached to that record.
        $this->correlationId = null;
        $this->host = null;
        $this->port = null;

        return $this;
    }

    public function download(
        string $remoteFilePath,
        ?string $localFileName = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        PathValidator::validateRemotePath($remoteFilePath);

        $this->retry(
            'download',
            fn(): true => $this->doDownload($remoteFilePath, $localFileName, $progress),
        );

        return $this;
    }

    private function doDownload(
        string $remoteFilePath,
        ?string $localFileName,
        ?ProgressListenerInterface $progress,
    ): true {
        $sftp = $this->requireSftp();

        $savePath = $this->localPrefix . ($localFileName ?? pathinfo($remoteFilePath, PATHINFO_BASENAME));

        $remoteUri = $this->ssh2->sftpStreamUri($sftp, $remoteFilePath);

        $remoteSize = $this->statSize($remoteFilePath);
        if ($remoteSize === null) {
            throw new TransferException('Remote file does not exist or no permissions to read: ' . $remoteFilePath);
        }

        $this->log('debug', 'SFTP download start', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
            'size' => $remoteSize,
        ]);
        $started = microtime(true);
        $progress?->started('download', $remoteSize);

        try {
            $remoteStream = @fopen($remoteUri, 'rb');
            if ($remoteStream === false) {
                throw new TransferException('Unable to open remote file: ' . $remoteFilePath);
            }

            try {
                $localStream = @fopen($savePath, 'wb');
                if ($localStream === false) {
                    throw new TransferException('Unable to open local file for writing: ' . $savePath);
                }

                try {
                    $this->copyWithProgress(
                        $remoteStream,
                        $localStream,
                        $progress,
                        'Failed to copy remote stream to local file: ' . $savePath,
                    );
                } finally {
                    fclose($localStream);
                }
            } finally {
                fclose($remoteStream);
            }

            if ($this->fileSizeVerificationEnabled) {
                clearstatcache(true, $savePath);
                $localSize = filesize($savePath);
                if ($localSize !== $remoteSize) {
                    throw new TransferException(\sprintf(
                        'File size mismatch after download of %s: remote=%d, local=%d',
                        $remoteFilePath,
                        $remoteSize,
                        $localSize,
                    ));
                }
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);

            throw $e;
        }

        $progress?->completed($remoteSize);
        $this->log('info', 'SFTP download ok', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
            'bytes' => $remoteSize,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return true;
    }

    public function upload(
        string $localFilePath,
        ?string $remoteFileName = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        $this->retry('upload', fn(): true => $this->doUpload($localFilePath, $remoteFileName, $progress));

        return $this;
    }

    private function doUpload(
        string $localFilePath,
        ?string $remoteFileName,
        ?ProgressListenerInterface $progress,
    ): true {
        $sftp = $this->requireSftp();

        if (! is_file($localFilePath)) {
            throw new TransferException('Local file does not exist or is not readable: ' . $localFilePath);
        }

        $finalPath = PathValidator::joinRemote(
            $this->remotePrefix,
            $remoteFileName ?? pathinfo($localFilePath, PATHINFO_BASENAME),
        );

        // Atomic write: stream the bytes into a hidden `.partial-{uuid}`
        // sibling, then ssh2_sftp_rename the partial onto the final path.
        // On any failure between fopen and rename, best-effort sftpUnlink
        // the partial so the directory doesn't accumulate half-written files.
        $useAtomic = $this->atomicUploads;
        $writePath = $useAtomic
            ? self::partialPath($finalPath, 'partial-' . bin2hex(random_bytes(4)))
            : $finalPath;
        $remoteUri = $this->ssh2->sftpStreamUri($sftp, $writePath);

        $localSize = filesize($localFilePath);
        $this->log('debug', 'SFTP upload start', [
            'local' => $localFilePath,
            'remote' => $finalPath,
            'size' => $localSize === false ? null : $localSize,
            'atomic' => $useAtomic,
        ]);
        $started = microtime(true);
        // filesize() returns false on stat failure (e.g., race); fall back to
        // unknown total rather than passing a negative sentinel to the listener.
        $startedSize = $localSize === false ? null : max(0, $localSize);
        $progress?->started('upload', $startedSize);

        try {
            $localStream = @fopen($localFilePath, 'rb');
            if ($localStream === false) {
                throw new TransferException('Unable to open local file for reading: ' . $localFilePath);
            }

            try {
                $remoteStream = @fopen($remoteUri, 'wb');
                if ($remoteStream === false) {
                    throw new TransferException('Unable to open remote file for writing: ' . $writePath);
                }

                try {
                    $this->copyWithProgress(
                        $localStream,
                        $remoteStream,
                        $progress,
                        'Failed to copy local stream to remote file: ' . $writePath,
                    );
                } finally {
                    fclose($remoteStream);
                }
            } finally {
                fclose($localStream);
            }

            if ($this->fileSizeVerificationEnabled) {
                $localSize = filesize($localFilePath);
                $remoteSize = $this->statSize($writePath);
                if ($localSize !== $remoteSize) {
                    throw new TransferException(\sprintf(
                        'File size mismatch after upload of %s: local=%d, remote=%d',
                        $localFilePath,
                        $localSize,
                        $remoteSize ?? -1,
                    ));
                }
            }

            if ($useAtomic && ! $this->ssh2->sftpRename($sftp, $writePath, $finalPath)) {
                throw new TransferException(
                    'Failed to copy local stream to remote file: '
                    . $finalPath . ' (rename of partial ' . $writePath . ' failed)',
                );
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);
            if ($useAtomic) {
                $this->cleanupPartial($sftp, $writePath);
            }

            throw $e;
        }

        $progress?->completed($startedSize ?? 0);
        $this->log('info', 'SFTP upload ok', [
            'local' => $localFilePath,
            'remote' => $finalPath,
            'bytes' => $startedSize,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
            'atomic' => $useAtomic,
        ]);

        return true;
    }

    public function uploadStream(
        mixed $stream,
        string $remoteFilePath,
        ?int $expectedSize = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        if (! is_resource($stream)) {
            throw new ConfigurationException('uploadStream(): $stream must be an open resource.');
        }
        if ($expectedSize !== null && $expectedSize < 0) {
            throw new ConfigurationException(\sprintf(
                'uploadStream(): $expectedSize must be >= 0; got %d.',
                $expectedSize,
            ));
        }
        $this->retry(
            'uploadStream',
            fn(): true => $this->doUploadStream($stream, $remoteFilePath, $expectedSize, $progress),
        );

        return $this;
    }

    /**
     * @param resource $stream
     * @param int<0, max>|null $expectedSize
     */
    private function doUploadStream(
        mixed $stream,
        string $remoteFilePath,
        ?int $expectedSize,
        ?ProgressListenerInterface $progress,
    ): true {
        $sftp = $this->requireSftp();

        $finalPath = PathValidator::joinRemote($this->remotePrefix, $remoteFilePath);

        $useAtomic = $this->atomicUploads;
        $writePath = $useAtomic
            ? self::partialPath($finalPath, 'partial-' . bin2hex(random_bytes(4)))
            : $finalPath;
        $remoteUri = $this->ssh2->sftpStreamUri($sftp, $writePath);

        $this->log('debug', 'SFTP upload-stream start', [
            'remote' => $finalPath,
            'expected_size' => $expectedSize,
            'atomic' => $useAtomic,
        ]);
        $started = microtime(true);
        $progress?->started('uploadStream', $expectedSize);

        $copied = 0;

        try {
            $remoteStream = @fopen($remoteUri, 'wb');
            if ($remoteStream === false) {
                throw new TransferException('Unable to open remote file for writing: ' . $writePath);
            }

            try {
                $copied = $this->copyWithProgress(
                    $stream,
                    $remoteStream,
                    $progress,
                    'Failed to copy local stream to remote file: ' . $writePath,
                );
            } finally {
                fclose($remoteStream);
            }

            if ($expectedSize !== null && $copied !== $expectedSize) {
                throw new TransferException(\sprintf(
                    'Stream length mismatch after upload of %s: expected=%d, copied=%d',
                    $finalPath,
                    $expectedSize,
                    $copied,
                ));
            }

            if ($useAtomic && ! $this->ssh2->sftpRename($sftp, $writePath, $finalPath)) {
                throw new TransferException(
                    'Failed to copy local stream to remote file: '
                    . $finalPath . ' (rename of partial ' . $writePath . ' failed)',
                );
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);
            if ($useAtomic) {
                $this->cleanupPartial($sftp, $writePath);
            }

            throw $e;
        }

        $progress?->completed($copied);
        $this->log('info', 'SFTP upload-stream ok', [
            'remote' => $finalPath,
            'bytes' => $copied,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
            'atomic' => $useAtomic,
        ]);

        return true;
    }

    /**
     * @return int<0, max>
     */
    public function downloadStream(
        string $remoteFilePath,
        mixed $stream,
        ?ProgressListenerInterface $progress = null,
    ): int {
        PathValidator::validateRemotePath($remoteFilePath);
        if (! is_resource($stream)) {
            throw new ConfigurationException('downloadStream(): $stream must be an open resource.');
        }

        return $this->retry(
            'downloadStream',
            fn(): int => $this->doDownloadStream($remoteFilePath, $stream, $progress),
        );
    }

    /**
     * @param resource $stream
     * @return int<0, max>
     */
    private function doDownloadStream(
        string $remoteFilePath,
        mixed $stream,
        ?ProgressListenerInterface $progress,
    ): int {
        $sftp = $this->requireSftp();

        $remoteSize = $this->statSize($remoteFilePath);
        if ($remoteSize === null) {
            throw new TransferException('Remote file does not exist or no permissions to read: ' . $remoteFilePath);
        }

        $remoteUri = $this->ssh2->sftpStreamUri($sftp, $remoteFilePath);
        $this->log('debug', 'SFTP download-stream start', [
            'remote' => $remoteFilePath,
            'size' => $remoteSize,
        ]);
        $started = microtime(true);
        $progress?->started('downloadStream', $remoteSize);

        $copied = 0;

        try {
            $remoteStream = @fopen($remoteUri, 'rb');
            if ($remoteStream === false) {
                throw new TransferException('Unable to open remote file: ' . $remoteFilePath);
            }

            try {
                $copied = $this->copyWithProgress(
                    $remoteStream,
                    $stream,
                    $progress,
                    'Failed to copy remote stream to caller stream for: ' . $remoteFilePath,
                );
            } finally {
                fclose($remoteStream);
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);

            throw $e;
        }

        $progress?->completed($copied);
        $this->log('info', 'SFTP download-stream ok', [
            'remote' => $remoteFilePath,
            'bytes' => $copied,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return $copied;
    }

    public function resumeUpload(
        string $localFilePath,
        string $remoteFileName,
        ?int $offset = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        $this->retry(
            'resumeUpload',
            fn(): true => $this->doResumeUpload($localFilePath, $remoteFileName, $offset, $progress),
        );

        return $this;
    }

    private function doResumeUpload(
        string $localFilePath,
        string $remoteFileName,
        ?int $offset,
        ?ProgressListenerInterface $progress,
    ): true {
        $sftp = $this->requireSftp();

        if (! is_file($localFilePath)) {
            throw new TransferException('Local file does not exist or is not readable: ' . $localFilePath);
        }

        $finalPath = PathValidator::joinRemote($this->remotePrefix, $remoteFileName);
        // Deterministic partial name — caller can call resumeUpload() again with
        // the same args and the auto-offset path will find what's there.
        $partialPath = self::partialPath($finalPath, 'resume');
        $partialUri = $this->ssh2->sftpStreamUri($sftp, $partialPath);

        // Auto-detect: if the caller didn't tell us where to resume from, look
        // at the existing partial. Missing → start at 0 (this becomes a fresh
        // upload).
        if ($offset === null) {
            $stat = $this->ssh2->sftpStat($sftp, $partialPath);
            $offset = ($stat !== false && isset($stat['size'])) ? $stat['size'] : 0;
        }
        if ($offset < 0) {
            throw new ConfigurationException(\sprintf('Resume offset must be >= 0; got %d.', $offset));
        }

        $localSize = filesize($localFilePath);
        if ($localSize !== false && $offset > $localSize) {
            throw new ConfigurationException(\sprintf(
                'Resume offset %d exceeds local file size %d for %s.',
                $offset,
                $localSize,
                $localFilePath,
            ));
        }

        // filesize() returns false on stat failure; fall back to unknown total.
        $startedSize = $localSize === false ? null : max(0, $localSize);
        $this->log('debug', 'SFTP resume upload start', [
            'local' => $localFilePath,
            'remote' => $finalPath,
            'partial' => $partialPath,
            'offset' => $offset,
            'size' => $startedSize,
        ]);
        $started = microtime(true);
        $progress?->started('resumeUpload', $startedSize);

        // NOTE: deliberately no partial-unlink in this catch arm. Resume
        // failures must preserve the partial so the next resumeUpload()
        // call can pick up where this attempt left off.
        try {
            $localStream = @fopen($localFilePath, 'rb');
            if ($localStream === false) {
                throw new TransferException('Unable to open local file for reading: ' . $localFilePath);
            }

            try {
                if ($offset > 0) {
                    self::seekOrThrow($localStream, $offset, 'local file', $localFilePath);
                }

                // Open the partial preserving existing bytes when resuming,
                // and create-or-truncate when starting fresh. libssh2's SFTP
                // wrapper accepts mode `ab` for open but its fwrite returns
                // false on append, so we use `r+b` + explicit seek when
                // $offset > 0 (preserves the bytes, no zero-padding) and
                // `wb` when $offset == 0 (fresh partial, overwrites any
                // stale one from a previous attempt).
                $partialMode = $offset > 0 ? 'r+b' : 'wb';
                $remoteStream = @fopen($partialUri, $partialMode);
                if ($remoteStream === false) {
                    throw new TransferException('Unable to open remote file for writing: ' . $partialPath);
                }

                try {
                    if ($offset > 0) {
                        self::seekOrThrow($remoteStream, $offset, 'remote partial', $partialPath);
                    }
                    $this->copyWithProgress(
                        $localStream,
                        $remoteStream,
                        $progress,
                        'Failed to copy local stream to remote file: ' . $partialPath,
                    );
                } finally {
                    fclose($remoteStream);
                }
            } finally {
                fclose($localStream);
            }

            if ($this->fileSizeVerificationEnabled && $localSize !== false) {
                $partialSize = $this->statSize($partialPath);
                if ($partialSize !== $localSize) {
                    throw new TransferException(\sprintf(
                        'File size mismatch after resume upload of %s: local=%d, partial=%d',
                        $localFilePath,
                        $localSize,
                        $partialSize ?? -1,
                    ));
                }
            }

            if (! $this->ssh2->sftpRename($sftp, $partialPath, $finalPath)) {
                // Same retryable wording as the upload rename failure — the
                // partial stays intact for the next attempt.
                throw new TransferException(
                    'Failed to copy local stream to remote file: '
                    . $finalPath . ' (rename of partial ' . $partialPath . ' failed)',
                );
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);

            throw $e;
        }

        $progress?->completed($startedSize ?? 0);
        $this->log('info', 'SFTP resume upload ok', [
            'local' => $localFilePath,
            'remote' => $finalPath,
            'bytes' => $startedSize,
            'resumed_from' => $offset,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return true;
    }

    public function resumeDownload(
        string $remoteFilePath,
        string $localFileName,
        ?int $offset = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        PathValidator::validateRemotePath($remoteFilePath);

        $this->retry(
            'resumeDownload',
            fn(): true => $this->doResumeDownload($remoteFilePath, $localFileName, $offset, $progress),
        );

        return $this;
    }

    private function doResumeDownload(
        string $remoteFilePath,
        string $localFileName,
        ?int $offset,
        ?ProgressListenerInterface $progress,
    ): true {
        $sftp = $this->requireSftp();

        $savePath = $this->localPrefix . $localFileName;
        $remoteSize = $this->statSize($remoteFilePath);
        if ($remoteSize === null) {
            throw new TransferException('Remote file does not exist or no permissions to read: ' . $remoteFilePath);
        }

        if ($offset === null) {
            clearstatcache(true, $savePath);
            $offset = is_file($savePath) ? (int) filesize($savePath) : 0;
        }
        if ($offset < 0) {
            throw new ConfigurationException(\sprintf('Resume offset must be >= 0; got %d.', $offset));
        }
        if ($offset > $remoteSize) {
            throw new ConfigurationException(\sprintf(
                'Resume offset %d exceeds remote file size %d for %s.',
                $offset,
                $remoteSize,
                $remoteFilePath,
            ));
        }

        $this->log('debug', 'SFTP resume download start', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
            'offset' => $offset,
            'size' => $remoteSize,
        ]);
        $started = microtime(true);

        if ($offset === $remoteSize) {
            // Already complete on disk. Skip the I/O so the resume call is a
            // safe no-op when callers retry after a previous success. Fire
            // started + completed so listeners still see a clean lifecycle.
            $progress?->started('resumeDownload', $remoteSize);
            $progress?->completed($remoteSize);
            $this->log('info', 'SFTP resume download noop', [
                'remote' => $remoteFilePath,
                'local' => $savePath,
                'bytes' => $remoteSize,
            ]);

            return true;
        }

        $progress?->started('resumeDownload', $remoteSize);

        try {
            $remoteUri = $this->ssh2->sftpStreamUri($sftp, $remoteFilePath);
            $remoteStream = @fopen($remoteUri, 'rb');
            if ($remoteStream === false) {
                throw new TransferException('Unable to open remote file: ' . $remoteFilePath);
            }

            try {
                if ($offset > 0) {
                    self::seekOrThrow($remoteStream, $offset, 'remote stream', $remoteFilePath);
                }

                $localStream = @fopen($savePath, $offset > 0 ? 'ab' : 'wb');
                if ($localStream === false) {
                    throw new TransferException('Unable to open local file for writing: ' . $savePath);
                }

                try {
                    $this->copyWithProgress(
                        $remoteStream,
                        $localStream,
                        $progress,
                        'Failed to copy remote stream to local file: ' . $savePath,
                    );
                } finally {
                    fclose($localStream);
                }
            } finally {
                fclose($remoteStream);
            }

            if ($this->fileSizeVerificationEnabled) {
                clearstatcache(true, $savePath);
                $localSize = filesize($savePath);
                if ($localSize !== $remoteSize) {
                    throw new TransferException(\sprintf(
                        'File size mismatch after resume download of %s: remote=%d, local=%d',
                        $remoteFilePath,
                        $remoteSize,
                        $localSize,
                    ));
                }
            }
        } catch (\Throwable $e) {
            $progress?->failed($e);

            throw $e;
        }

        $progress?->completed($remoteSize);
        $this->log('info', 'SFTP resume download ok', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
            'bytes' => $remoteSize,
            'resumed_from' => $offset,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return true;
    }

    /**
     * Best-effort cleanup of a partial file left behind by a failed upload.
     * Errors are swallowed (logged at warning) — the partial may already have
     * been unlinked, the peer may be gone, or the server may forbid unlink;
     * propagating would mask the original upload failure that triggered this.
     *
     * @param resource $sftp
     */
    private function cleanupPartial(mixed $sftp, string $partialPath): void
    {
        try {
            $this->ssh2->sftpUnlink($sftp, $partialPath);
        } catch (\Throwable $e) {
            $this->log('warning', 'SFTP partial cleanup failed', [
                'partial' => $partialPath,
                'exception' => $e::class,
                'reason' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Chunked stream copy with progress emission. Replaces stream_copy_to_stream
     * for all transfer paths so callers can observe per-chunk progress and so
     * the chunk size is tunable.
     *
     * Deliberately does NOT call started() / completed() / failed() — the
     * lifecycle terminator depends on whether the *whole* operation (including
     * size verification, rename, etc.) succeeded, and only the caller knows.
     * Helper just emits progress() per chunk.
     *
     * Avoids feof() because some libssh2 stream wrappers return true on it
     * incorrectly. fread === '' is a more reliable EOF signal.
     *
     * @param resource $from
     * @param resource $to
     * @return int<0, max> total bytes copied
     */
    private function copyWithProgress(
        mixed $from,
        mixed $to,
        ?ProgressListenerInterface $progress,
        string $failureMessage,
    ): int {
        $copied = 0;
        while (true) {
            $buf = @fread($from, $this->chunkSize);
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
     * stream wrappers (non-seekable sources). Without it a returned `-1`
     * would silently leave the read cursor at zero and produce a corrupted
     * resumed transfer — much worse than a clean throw.
     *
     * @param resource $stream
     */
    private static function seekOrThrow(mixed $stream, int $offset, string $contextLabel, string $path): void
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
     * - "/in/report.csv" → "/in/.report.csv.partial-abc12345"
     * - "/report.csv"   → "/.report.csv.partial-abc12345"
     * - "report.csv"    → ".report.csv.partial-abc12345"
     */
    private static function partialPath(string $remote, string $suffix): string
    {
        $base = basename($remote);
        $dir = \dirname($remote);
        $partial = '.' . $base . '.' . $suffix;
        if ($dir === '.' || $dir === '') {
            return $partial;
        }

        return rtrim($dir, '/') . '/' . $partial;
    }

    public function scpDownload(string $remoteFilePath, ?string $localFileName = null): self
    {
        PathValidator::validateRemotePath($remoteFilePath);

        $this->retry('scpDownload', fn(): true => $this->doScpDownload($remoteFilePath, $localFileName));

        return $this;
    }

    private function doScpDownload(string $remoteFilePath, ?string $localFileName): true
    {
        $session = $this->requireSession();
        $sftp = $this->requireSftp();

        if ($this->ssh2->sftpStat($sftp, $remoteFilePath) === false) {
            throw new TransferException('Remote file does not exist or no permissions to read: ' . $remoteFilePath);
        }

        $savePath = $this->localPrefix . ($localFileName ?? pathinfo($remoteFilePath, PATHINFO_BASENAME));

        $this->log('debug', 'SCP download start', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
        ]);
        $started = microtime(true);

        if (! $this->ssh2->scpRecv($session, $remoteFilePath, $savePath)) {
            throw new TransferException('Could not SCP-download file: ' . $remoteFilePath);
        }

        $this->log('info', 'SCP download ok', [
            'remote' => $remoteFilePath,
            'local' => $savePath,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return true;
    }

    public function scpUpload(string $localFilePath, ?string $remoteFileName = null): self
    {
        $this->retry('scpUpload', fn(): true => $this->doScpUpload($localFilePath, $remoteFileName));

        return $this;
    }

    private function doScpUpload(string $localFilePath, ?string $remoteFileName): true
    {
        $session = $this->requireSession();

        if (! is_file($localFilePath)) {
            throw new TransferException('Local file does not exist or is not readable: ' . $localFilePath);
        }

        $savePath = PathValidator::joinRemote(
            $this->remotePrefix,
            $remoteFileName ?? pathinfo($localFilePath, PATHINFO_BASENAME),
        );

        $this->log('debug', 'SCP upload start', [
            'local' => $localFilePath,
            'remote' => $savePath,
        ]);
        $started = microtime(true);

        if (! $this->ssh2->scpSend($session, $localFilePath, $savePath, 0o644)) {
            throw new TransferException('Could not SCP-upload file: ' . $localFilePath);
        }

        $this->log('info', 'SCP upload ok', [
            'local' => $localFilePath,
            'remote' => $savePath,
            'duration_ms' => (int) ((microtime(true) - $started) * 1000),
        ]);

        return true;
    }

    public function remove(string $remoteFilePath): self
    {
        $sftp = $this->requireSftp();
        $fullPath = PathValidator::joinRemote($this->remotePrefix, $remoteFilePath);

        if ($this->ssh2->sftpStat($sftp, $fullPath) === false) {
            throw new RemoteFilesystemException('Remote file does not exist or no permissions to read: ' . $fullPath);
        }

        if (! $this->ssh2->sftpUnlink($sftp, $fullPath)) {
            throw new RemoteFilesystemException('Unable to remove remote file: ' . $fullPath);
        }

        $this->log('debug', 'SFTP remove ok', ['remote' => $fullPath]);

        return $this;
    }

    public function rename(string $remoteFilePath, string $newRemoteFilePath): self
    {
        $sftp = $this->requireSftp();
        $from = PathValidator::joinRemote($this->remotePrefix, $remoteFilePath);
        $to = PathValidator::joinRemote($this->remotePrefix, $newRemoteFilePath);

        if ($this->ssh2->sftpStat($sftp, $from) === false) {
            throw new RemoteFilesystemException('Remote source does not exist or no permissions to read: ' . $from);
        }

        if (! $this->ssh2->sftpRename($sftp, $from, $to)) {
            throw new RemoteFilesystemException(\sprintf('Unable to rename %s to %s.', $from, $to));
        }

        $this->log('debug', 'SFTP rename ok', ['from' => $from, 'to' => $to]);

        return $this;
    }

    public function getFileList(string $remotePath, bool $includeDotEntries = false): array
    {
        PathValidator::validateRemotePath($remotePath);

        $sftp = $this->requireSftp();
        $uri = $this->ssh2->sftpStreamUri($sftp, $remotePath);

        if (@stat($uri) === false) {
            throw new RemoteFilesystemException('Remote directory does not exist or no permissions to read: ' . $remotePath);
        }

        $handle = @opendir($uri);
        if ($handle === false) {
            throw new RemoteFilesystemException('Unable to open remote directory: ' . $remotePath);
        }

        $files = [];

        try {
            while (($entry = readdir($handle)) !== false) {
                if (! $includeDotEntries && ($entry === '.' || $entry === '..')) {
                    continue;
                }
                $files[] = $entry;
            }
        } finally {
            closedir($handle);
        }

        return $files;
    }

    /**
     * @return array<int|string, int>
     */
    public function stat(string $remotePath): array
    {
        PathValidator::validateRemotePath($remotePath);

        $sftp = $this->requireSftp();
        $result = $this->ssh2->sftpStat($sftp, $remotePath);
        if ($result === false) {
            throw new RemoteFilesystemException('Unable to stat remote path: ' . $remotePath);
        }

        return $result;
    }

    public function makeDirectory(string $path, int $mode = 0o755, bool $recursive = false): self
    {
        PathValidator::validateRemotePath($path);

        $sftp = $this->requireSftp();

        if (! $this->ssh2->sftpMkdir($sftp, $path, $mode, $recursive)) {
            throw new RemoteFilesystemException('Unable to create remote directory: ' . $path);
        }

        $this->log('debug', 'SFTP mkdir ok', ['path' => $path, 'mode' => $mode, 'recursive' => $recursive]);

        return $this;
    }

    public function removeDirectory(string $path): self
    {
        PathValidator::validateRemotePath($path);

        $sftp = $this->requireSftp();

        if (! $this->ssh2->sftpRmdir($sftp, $path)) {
            throw new RemoteFilesystemException('Unable to remove remote directory: ' . $path);
        }

        $this->log('debug', 'SFTP rmdir ok', ['path' => $path]);

        return $this;
    }

    /**
     * Recursively yield every entry under `$remoteDir`, post-order (children
     * before their parent). Useful for `rm -rf`, archive backup, audit walks.
     *
     * Symlinks are yielded as {@see EntryType::Symlink} but their targets are
     * NOT followed — even if they point at directories. Cycle detection /
     * follow semantics are explicit follow-ups (see PRODUCTION_GRADE.md §P3).
     *
     * @return iterable<RemoteEntry>
     * @throws RemoteFilesystemException
     */
    public function walk(string $remoteDir): iterable
    {
        PathValidator::validateRemotePath($remoteDir);
        $this->requireSftp(); // surface "not connected" before the generator runs

        return $this->walkInternal($remoteDir);
    }

    /**
     * Recursive directory upload. Walks the local tree top-down, mkdir's
     * each subdir on the remote, and delegates per-file transfer to
     * {@see upload()} — so atomic write, retry, file-size verification, and
     * progress emission all apply to each file in turn.
     *
     * Symlinks under the local tree are skipped (recorded in
     * {@see UploadResult::$skipped}). Conflict mode is overwrite-only for
     * 1.1 (atomic rename handles it for files; mkdir is idempotent).
     *
     * @throws ConfigurationException invalid path or missing/unreadable local dir
     * @throws TransferException per-file failure
     * @throws RemoteFilesystemException mkdir failed
     */
    public function uploadDirectory(
        string $localDir,
        string $remoteDir,
        bool $createRemoteDir = true,
        ?ProgressListenerInterface $progress = null,
    ): UploadResult {
        if (! is_dir($localDir)) {
            throw new ConfigurationException(
                'uploadDirectory(): local directory does not exist or is not a directory: ' . $localDir,
            );
        }
        PathValidator::validateRemotePath($remoteDir);
        $remoteDir = rtrim($remoteDir, '/');

        $sftp = $this->requireSftp();
        if ($createRemoteDir && $this->ssh2->sftpStat($sftp, $remoteDir) === false) {
            $this->ssh2->sftpMkdir($sftp, $remoteDir, 0o755, true);
        }

        // Use $localDir as-is for the relative-path math; the is_dir() check
        // above already filtered missing roots and adding realpath() here
        // would only protect against a TOCTOU delete between the two calls
        // (which propagates as a clear DirectoryIterator error anyway).
        $localRoot = rtrim($localDir, \DIRECTORY_SEPARATOR);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(
                $localRoot,
                \RecursiveDirectoryIterator::SKIP_DOTS,
            ),
            \RecursiveIteratorIterator::SELF_FIRST,
        );

        $filesTransferred = 0;
        $bytesTransferred = 0;
        $skipped = [];

        $this->log('debug', 'SFTP upload directory start', [
            'local' => $localRoot,
            'remote' => $remoteDir,
        ]);

        /** @var \SplFileInfo $info */
        foreach ($iterator as $info) {
            $relative = substr($info->getPathname(), \strlen($localRoot) + 1);
            // Normalise Windows-style separators in the relative path so the
            // remote layout stays POSIX-shaped regardless of host OS.
            $relativeRemote = str_replace(\DIRECTORY_SEPARATOR, '/', $relative);
            $remotePath = $remoteDir . '/' . $relativeRemote;

            if ($info->isLink()) {
                $skipped[] = $info->getPathname();
                $this->log('debug', 'SFTP upload directory skipped symlink', [
                    'local' => $info->getPathname(),
                ]);

                continue;
            }
            if ($info->isDir()) {
                if ($this->ssh2->sftpStat($sftp, $remotePath) === false
                    && ! $this->ssh2->sftpMkdir($sftp, $remotePath, 0o755, false)) {
                    throw new RemoteFilesystemException(
                        'uploadDirectory(): unable to create remote directory ' . $remotePath,
                    );
                }

                continue;
            }
            // Regular files (and any other entry type) flow through upload()
            // — the existing "Local file does not exist or is not readable"
            // wording surfaces sockets / FIFOs / devices with a clear error,
            // matching the documented "abort on first failure" default.
            $this->upload($info->getPathname(), $remotePath, $progress);
            $filesTransferred++;
            $size = $info->getSize();
            $bytesTransferred += max(0, (int) $size);
        }

        $this->log('info', 'SFTP upload directory ok', [
            'local' => $localRoot,
            'remote' => $remoteDir,
            'files' => $filesTransferred,
            'bytes' => $bytesTransferred,
            'skipped' => \count($skipped),
        ]);

        return new UploadResult($filesTransferred, $bytesTransferred, $skipped);
    }

    /**
     * Recursive directory download. Mirrors {@see uploadDirectory()} in the
     * opposite direction: walks the remote tree top-down, mkdir's each
     * subdir locally, and delegates per-file transfer to {@see download()}.
     *
     * Symlinks on the remote are skipped (recorded in
     * {@see DownloadResult::$skipped}).
     *
     * @throws ConfigurationException invalid remote path
     * @throws TransferException per-file failure
     * @throws RemoteFilesystemException remote stat / readdir failed
     */
    public function downloadDirectory(
        string $remoteDir,
        string $localDir,
        ?ProgressListenerInterface $progress = null,
    ): DownloadResult {
        PathValidator::validateRemotePath($remoteDir);
        $remoteDir = rtrim($remoteDir, '/');

        if (! is_dir($localDir) && ! @mkdir($localDir, 0o755, true) && ! is_dir($localDir)) {
            throw new ConfigurationException(
                'downloadDirectory(): local directory could not be created: ' . $localDir,
            );
        }
        $localDir = rtrim($localDir, '/');

        $filesTransferred = 0;
        $bytesTransferred = 0;
        $skipped = [];

        $this->log('debug', 'SFTP download directory start', [
            'remote' => $remoteDir,
            'local' => $localDir,
        ]);

        $this->downloadDirectoryRecurse(
            $remoteDir,
            $localDir,
            $progress,
            $filesTransferred,
            $bytesTransferred,
            $skipped,
        );

        $this->log('info', 'SFTP download directory ok', [
            'remote' => $remoteDir,
            'local' => $localDir,
            'files' => $filesTransferred,
            'bytes' => $bytesTransferred,
            'skipped' => \count($skipped),
        ]);

        // Clamp on the boundary: the helper widens int<0, max> back to
        // plain int through the recursive by-ref parameter, but the
        // counters are only ever incremented so the runtime invariant
        // holds. max(0, ...) re-establishes the type for the value object.
        return new DownloadResult(max(0, $filesTransferred), max(0, $bytesTransferred), $skipped);
    }

    /**
     * Remove a remote directory and everything beneath it.
     *
     * Recurses post-order: files (and symlinks) are unlinked, empty
     * directories are rmdir'd. The root `$remoteDir` itself is removed
     * last. Server permissions still apply — a write-protected leaf
     * surfaces a {@see RemoteFilesystemException} from the underlying
     * unlink/rmdir, which propagates verbatim so callers can act on it.
     *
     * @throws RemoteFilesystemException
     */
    public function removeDirectoryTree(string $remoteDir): self
    {
        PathValidator::validateRemotePath($remoteDir);
        $remoteDir = rtrim($remoteDir, '/');
        $sftp = $this->requireSftp();

        $this->log('debug', 'SFTP remove directory tree start', ['remote' => $remoteDir]);
        $this->removeTreeRecurse($remoteDir);

        if (! $this->ssh2->sftpRmdir($sftp, $remoteDir)) {
            throw new RemoteFilesystemException(
                'removeDirectoryTree(): unable to remove remote directory ' . $remoteDir,
            );
        }
        $this->log('info', 'SFTP remove directory tree ok', ['remote' => $remoteDir]);

        return $this;
    }

    /**
     * Yield recursive entries post-order. Lives outside walk() so the
     * generator semantics don't defer the "no connection" check to the
     * first iteration step.
     *
     * @return \Generator<RemoteEntry>
     */
    private function walkInternal(string $remoteDir): \Generator
    {
        $remoteDir = rtrim($remoteDir, '/');
        $sftp = $this->requireSftp();

        foreach ($this->getFileList($remoteDir) as $name) {
            $path = $remoteDir . '/' . $name;
            $type = $this->entryType($path);
            if ($type === EntryType::Directory) {
                yield from $this->walkInternal($path);
                yield new RemoteEntry($path, EntryType::Directory, null);

                continue;
            }
            $size = null;
            if ($type === EntryType::File) {
                $size = $this->statSize($path);
            }
            yield new RemoteEntry($path, $type, $size);
        }
        unset($sftp); // silence "unused" — requireSftp is the contract check
    }

    /**
     * Post-order recursive cleanup body shared by removeDirectoryTree().
     * Walks each entry, unlinks files + symlinks, rmdir's empty
     * subdirectories. Does NOT remove `$remoteDir` itself — caller does
     * that as the last step so the root error message is unambiguous.
     */
    private function removeTreeRecurse(string $remoteDir): void
    {
        $sftp = $this->requireSftp();

        foreach ($this->getFileList($remoteDir) as $name) {
            $path = $remoteDir . '/' . $name;
            $type = $this->entryType($path);
            if ($type === EntryType::Directory) {
                $this->removeTreeRecurse($path);
                if (! $this->ssh2->sftpRmdir($sftp, $path)) {
                    throw new RemoteFilesystemException(
                        'removeDirectoryTree(): unable to remove remote directory ' . $path,
                    );
                }

                continue;
            }
            // Files, symlinks, other — all go through sftpUnlink.
            if (! $this->ssh2->sftpUnlink($sftp, $path)) {
                throw new RemoteFilesystemException(
                    'removeDirectoryTree(): unable to remove remote entry ' . $path,
                );
            }
        }
    }

    /**
     * Recursive worker for downloadDirectory(). Pre-order: create local
     * subdir, then download files within, then recurse into nested dirs.
     *
     * @param list<string> $skipped
     * @param-out list<string> $skipped
     */
    private function downloadDirectoryRecurse(
        string $remoteDir,
        string $localDir,
        ?ProgressListenerInterface $progress,
        int &$filesTransferred,
        int &$bytesTransferred,
        array &$skipped,
    ): void {
        foreach ($this->getFileList($remoteDir) as $name) {
            $remotePath = $remoteDir . '/' . $name;
            $localPath = $localDir . '/' . $name;
            $type = $this->entryType($remotePath);
            if ($type === EntryType::Symlink || $type === EntryType::Other) {
                $skipped[] = $remotePath;

                continue;
            }
            if ($type === EntryType::Directory) {
                if (! is_dir($localPath) && ! @mkdir($localPath, 0o755, true) && ! is_dir($localPath)) {
                    throw new RemoteFilesystemException(
                        'downloadDirectory(): unable to create local directory ' . $localPath,
                    );
                }
                $this->downloadDirectoryRecurse(
                    $remotePath,
                    $localPath,
                    $progress,
                    $filesTransferred,
                    $bytesTransferred,
                    $skipped,
                );

                continue;
            }
            // EntryType::File
            $this->download($remotePath, $localPath, $progress);
            $filesTransferred++;
            $size = $this->statSize($remotePath);
            if ($size !== null) {
                $bytesTransferred += $size;
            }
        }
    }

    /**
     * Classify a remote path using lstat() via the SFTP stream wrapper.
     *
     * Returns:
     *  - Directory for `S_IFDIR` entries
     *  - Symlink for `S_IFLNK` (lstat preserves the link mode bits)
     *  - File for `S_IFREG`
     *  - Other for sockets / FIFOs / devices, or when stat fails entirely
     *
     * Falls back to a follow-symlink sftpStat if lstat returns false — some
     * libssh2 stream wrappers (older builds) don't expose the link variant.
     */
    private function entryType(string $remotePath): EntryType
    {
        $sftp = $this->requireSftp();
        $uri = $this->ssh2->sftpStreamUri($sftp, $remotePath);
        clearstatcache(true, $uri);
        $stat = @lstat($uri);
        if ($stat === false) {
            // lstat unsupported or path gone — fall back to the SFTP stat
            // which always follows symlinks. We'll mis-classify a symlink
            // to a dir as Directory in that case, which is acceptable
            // degradation for ancient libssh2 builds.
            $sftpStat = $this->ssh2->sftpStat($sftp, $remotePath);
            if ($sftpStat === false || ! isset($sftpStat['mode'])) {
                return EntryType::Other;
            }
            $mode = $sftpStat['mode'];
        } else {
            $mode = $stat['mode'];
        }

        return match ($mode & 0o170000) {
            0o040000 => EntryType::Directory,
            0o120000 => EntryType::Symlink,
            0o100000 => EntryType::File,
            default => EntryType::Other,
        };
    }

    public function fileExists(string $path): bool
    {
        PathValidator::validateRemotePath($path);

        $sftp = $this->requireSftp();
        $uri = $this->ssh2->sftpStreamUri($sftp, $path);
        clearstatcache(true, $uri);

        return @file_exists($uri);
    }

    public function ping(): bool
    {
        $sftp = $this->sftp;
        if ($sftp === null) {
            return false;
        }

        // Cheap liveness probe: stat the SFTP root. The adapter already
        // @-suppresses warnings, so a torn-down peer returns false rather
        // than throwing — matches the contract that ping() NEVER raises.
        return $this->ssh2->sftpStat($sftp, '/') !== false;
    }

    /**
     * @phpstan-assert !null $this->sshSession
     * @return resource
     */
    private function requireSession(): mixed
    {
        if ($this->sshSession === null) {
            throw new ConnectionException('SSH session is not established. Call connect() first.');
        }

        return $this->sshSession;
    }

    /**
     * @phpstan-assert !null $this->sftp
     * @phpstan-assert !null $this->sshSession
     * @return resource
     */
    private function requireSftp(): mixed
    {
        if ($this->sftp === null) {
            throw new ConnectionException('SFTP subsystem is not initialised. Call connect() first.');
        }

        return $this->sftp;
    }

    /**
     * Transient-failure substrings inside `TransferException::getMessage()`
     * that the client treats as retryable in addition to all
     * `ConnectionException` failures.
     *
     * Message-matching is the pragmatic compromise: we can't introduce a new
     * exception subtype per transient cause without breaking the contract,
     * and the messages themselves are stable strings produced by this class.
     * Anything not on this list is treated as permanent (caller error, real
     * filesystem state) and propagated immediately.
     */
    private const RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS = [
        'Failed to copy',
        'Unable to open remote',
        'Could not SCP-download',
        'Could not SCP-upload',
    ];

    /**
     * Wrap an operation in the configured retry policy + lazy reconnect.
     *
     * Decision flow:
     * - If $operation throws an exception that's hard-NEVER (auth, config,
     *   path validation), propagate immediately — no retry, no policy call.
     * - Otherwise ask the policy for the next delay. 0 means "give up";
     *   propagate the most recent exception.
     * - Before sleeping, if a session is established but ping() reports it
     *   dead, run a one-shot doConnect() to revive it. If that itself
     *   throws, propagate (the retry policy still bounds total attempts via
     *   maxRetries, so we can't loop forever).
     * - Sleep, then re-invoke $operation.
     *
     * The "lazy reconnect" branch is naturally skipped during the initial
     * `connect()` (no session yet) and during the first retry of `connect`
     * (we are connect, that's the whole point).
     *
     * @template T
     * @param \Closure(): T $operation
     * @return T
     */
    private function retry(string $opName, \Closure $operation): mixed
    {
        $attempt = 0;
        while (true) {
            try {
                return $operation();
            } catch (SshException $e) {
                if (! self::isRetryable($e)) {
                    throw $e;
                }
                $attempt++;
                $delayMs = $this->retryPolicy->nextDelayMs($attempt, $e);
                if ($delayMs === 0) {
                    throw $e;
                }

                $this->log('warning', $opName . ' failed, retrying', [
                    'op' => $opName,
                    'attempt' => $attempt,
                    'delay_ms' => $delayMs,
                    'exception' => $e::class,
                    'reason' => $e->getMessage(),
                ]);

                // Lazy reconnect: if a session was up and is now dead, revive it
                // before retrying. doConnect() runs OUTSIDE the retry wrapper to
                // avoid recursion; a reconnect failure propagates and ends the loop.
                if ($this->sshSession !== null && ! $this->ping()) {
                    $this->log('warning', 'session looks dead, reconnecting');
                    $this->sftp = null;
                    $this->sshSession = null;
                    $this->doConnect();
                }

                // $delayMs is > 0 here (the === 0 branch above returned).
                usleep($delayMs * 1000);
            }
        }
    }

    /**
     * Classify whether $e is in principle retryable.
     *
     * Hard NEVER:
     * - {@see ConfigurationException} / {@see InvalidPathException}: caller bug,
     *   retrying executes the same wrong call again.
     * - {@see AuthenticationException}: retrying password-rejected attempts is
     *   how IP bans get earned.
     *
     * Retryable:
     * - Anything that is a {@see ConnectionException}: transport-level.
     * - {@see TransferException} whose message starts with a known transient
     *   fragment (see {@see self::RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS}).
     *
     * Everything else is treated as permanent — better to error visibly
     * than to mask a real bug behind a retry loop.
     */
    private static function isRetryable(SshException $e): bool
    {
        if ($e instanceof InvalidPathException) {
            return false;
        }
        if ($e instanceof ConfigurationException) {
            return false;
        }
        if ($e instanceof AuthenticationException) {
            return false;
        }
        if ($e instanceof ConnectionException) {
            return true;
        }
        if ($e instanceof TransferException) {
            $msg = $e->getMessage();
            foreach (self::RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS as $fragment) {
                if (str_contains($msg, $fragment)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Run the authentication leg matching the credentials' mode.
     *
     * Lives on the client (not on Credentials) so the {@see CredentialsInterface}
     * contract can be pure-data and ext-ssh2-free — see P1 in PRODUCTION_GRADE.md.
     *
     * @param resource $session
     */
    private function authorize(mixed $session, CredentialsInterface $credentials): void
    {
        $username = $credentials->getUsername();
        $mode = $credentials->getMode();

        $ok = match ($mode) {
            AuthMode::None => $this->ssh2->authNone($session, $username),
            AuthMode::Password => $this->ssh2->authPassword(
                $session,
                $username,
                (string) $credentials->getPassword(),
            ),
            AuthMode::PublicKey => $this->ssh2->authPublicKey(
                $session,
                $username,
                (string) $credentials->getPublicKey(),
                (string) $credentials->getPrivateKey(),
                $credentials->getPassphrase(),
            ),
            AuthMode::Both => $this->authorizeBoth($session, $credentials),
        };

        if (! $ok) {
            $this->log('notice', 'SSH authentication rejected', [
                'user' => $username,
                'mode' => $mode->name,
            ]);

            throw new AuthenticationException(
                'SSH authentication failed for user "' . $username . '" using ' . $mode->name . ' mode.',
            );
        }

        $this->log('info', 'SSH authentication ok', [
            'user' => $username,
            'mode' => $mode->name,
        ]);
    }

    /**
     * Multi-factor: pubkey AND password must both succeed. A server requiring
     * only one will accept either leg; a server configured
     * `AuthenticationMethods publickey,password` accepts only both.
     *
     * @param resource $session
     */
    private function authorizeBoth(mixed $session, CredentialsInterface $credentials): bool
    {
        $pubkeyOk = $this->ssh2->authPublicKey(
            $session,
            $credentials->getUsername(),
            (string) $credentials->getPublicKey(),
            (string) $credentials->getPrivateKey(),
            $credentials->getPassphrase(),
        );

        $passwordOk = $this->ssh2->authPassword(
            $session,
            $credentials->getUsername(),
            (string) $credentials->getPassword(),
        );

        return $pubkeyOk && $passwordOk;
    }

    /**
     * @return int<0, max>|null
     */
    private function statSize(string $remotePath): ?int
    {
        $sftp = $this->requireSftp();
        $stat = $this->ssh2->sftpStat($sftp, $remotePath);
        if ($stat === false || ! isset($stat['size'])) {
            return null;
        }

        // SFTP / POSIX file sizes are always non-negative, but the stub-derived
        // type for ssh2_sftp_stat is plain int. Clamp so PHPStan can prove the
        // non-negative invariant for downstream callers (progress listener
        // expects int<0, max>).
        return max(0, $stat['size']);
    }

    /**
     * Single funnel for every log emission in this class. Auto-merges the
     * connection-scoped base context (correlation_id + host + port once set)
     * with the caller-supplied static context and the per-call extras.
     *
     * Keep secrets OUT of the $context argument: a unit test
     * (LoggerRedactionTest) lints this file for the literal tokens
     * "password" / "passphrase" inside log calls and fails the build if any
     * appear.
     *
     * @param array<string, mixed> $context per-call extras
     */
    private function log(string $level, string $message, array $context = []): void
    {
        $base = [];
        if ($this->correlationId !== null) {
            $base['correlation_id'] = $this->correlationId;
        }
        if ($this->host !== null) {
            $base['host'] = $this->host;
        }
        if ($this->port !== null) {
            $base['port'] = $this->port;
        }

        $this->logger?->log($level, $message, array_merge($base, $this->logContext, $context));
    }

    private function probeTcp(string $host, int $port, int $timeoutSeconds): void
    {
        $errno = 0;
        $errstr = '';
        $probe = @stream_socket_client(
            \sprintf('tcp://%s:%d', $host, $port),
            $errno,
            $errstr,
            (float) $timeoutSeconds,
        );
        if ($probe === false) {
            throw new ConnectionException(\sprintf(
                'TCP probe to %s:%d failed within %ds: %s (%d).',
                $host,
                $port,
                $timeoutSeconds,
                $errstr,
                $errno,
            ));
        }
        fclose($probe);
    }
}
