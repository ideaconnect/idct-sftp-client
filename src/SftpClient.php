<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh;

use IDCT\Networking\Ssh\Auth\AuthDispatcher;
use IDCT\Networking\Ssh\Auth\AuthFailureRateLimiter;
use IDCT\Networking\Ssh\Auth\CredentialsInterface;
use IDCT\Networking\Ssh\Auth\CredentialsLoaderInterface;
use IDCT\Networking\Ssh\Checksum\RemoteHasherInterface;
use IDCT\Networking\Ssh\Directory\ConflictPolicy;
use IDCT\Networking\Ssh\Directory\DirectoryFailure;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\EntryType;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\SymlinkPolicy;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\KnownHosts\HostKeyVerifier;
use IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy;
use IDCT\Networking\Ssh\Path\PathValidator;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy;
use IDCT\Networking\Ssh\Retry\RetryClassifier;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;
use IDCT\Networking\Ssh\Security\SecurityProfile;
use IDCT\Networking\Ssh\Ssh2\Ssh2Functions;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Transfer\StreamCopier;
use IDCT\Networking\Ssh\Transfer\TcpProbe;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;

final class SftpClient implements SftpClientInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    /**
     * Static credentials used by {@see connect()} when no per-host
     * loader is installed. Mutually exclusive with {@see $credentialsLoader}.
     */
    private ?CredentialsInterface $credentials = null;

    /**
     * Per-host credentials loader. Takes precedence over {@see $credentials}
     * when set — every connect() re-resolves credentials via the loader so
     * a single client can serve multiple hosts with different secrets.
     */
    private ?CredentialsLoaderInterface $credentialsLoader = null;

    /**
     * Live SSH session resource from {@see Ssh2FunctionsInterface::connect()}.
     * `null` before {@see connect()} and after {@see close()}.
     *
     * @var resource|null
     */
    private mixed $sshSession = null;

    /**
     * Live SFTP subsystem resource from {@see Ssh2FunctionsInterface::sftp()}.
     * `null` before {@see connect()} and after {@see close()}.
     *
     * @var resource|null
     */
    private mixed $sftp = null;

    /**
     * Prepended verbatim to every LOCAL path. `''` disables prefixing.
     * Absolute paths (those starting with `/`) bypass the prefix.
     */
    private string $localPrefix = '';

    /**
     * Prepended via {@see PathValidator::joinRemote()} to every REMOTE
     * path. `''` disables prefixing. Absolute paths bypass the prefix.
     */
    private string $remotePrefix = '';

    /**
     * When true, every upload/download/resume verifies the post-transfer
     * byte count via a stat round-trip and throws on mismatch. Defaults
     * to the constructor's `$enableFileSizeVerification` flag (false).
     */
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
     * Bytes per fread/fwrite call inside {@see StreamCopier::copy()}. 1 MiB
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
    /** TCP probe timeout from the last connect(); `null` means no pre-probe. */
    private ?int $timeoutSeconds = null;

    /** Expected host-key fingerprint to match against on connect; `null` skips the check. */
    private ?string $expectedFingerprint = null;

    /** Algorithm used to compute `$expectedFingerprint`. */
    private FingerprintAlgorithm $fingerprintAlgorithm = FingerprintAlgorithm::Sha256;

    /** Encoding (hex / raw) `$expectedFingerprint` is given in. */
    private FingerprintEncoding $fingerprintEncoding = FingerprintEncoding::Hex;

    /** Path to OpenSSH-format known_hosts file (with optional TOFU entries); `null` disables file-based verification. */
    private ?string $knownHostsFile = null;

    /** What to do when the host isn't in `$knownHostsFile` — Reject (raise) or TrustOnFirstUse (append + proceed). */
    private UnknownHostPolicy $onUnknownHost = UnknownHostPolicy::Reject;

    /** Cipher / MAC / KEX preset; `null` and Compatible both leave libssh2 defaults untouched. */
    private ?SecurityProfile $securityProfile = null;

    /** Optional per-process backoff after consecutive auth failures; `null` disables. */
    private ?AuthFailureRateLimiter $authRateLimiter = null;

    /** Server-side checksum verifier; `null` disables checksum verification. */
    private ?RemoteHasherInterface $remoteHasher = null;

    /** Retry policy wrapping connect / upload / download / scp; defaulted in the constructor. */
    private RetryPolicyInterface $retryPolicy;

    /**
     * Caller-supplied static context merged into every log record (e.g.
     * request_id, tenant_id). Set via {@see setLogContext()}.
     *
     * @var array<string, mixed>
     */
    private array $logContext = [];

    /**
     * @param bool $enableFileSizeVerification  Enable post-transfer
     *        byte-count verification (one extra stat per file). Off by
     *        default — flip on for paranoid integrity checks.
     * @param Ssh2FunctionsInterface|null $ssh2 ext-ssh2 adapter; pass a
     *        fake in tests, `null` uses the real {@see Ssh2Functions}.
     * @param RetryPolicyInterface|null $retryPolicy Retry strategy; `null`
     *        uses {@see ExponentialBackoffRetryPolicy} with default knobs.
     * @param bool $atomicUploads Write to a hidden `.partial-{uuid}` sibling
     *        and rename onto the final path. On by default.
     * @param int $chunkSize fread/fwrite buffer size in bytes; defaults
     *        to {@see DEFAULT_CHUNK_SIZE} (1 MiB). Must be >= 1.
     *
     * @throws ConfigurationException when `$chunkSize` is less than 1.
     */
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

    /** {@inheritDoc} */
    public function setRetryPolicy(RetryPolicyInterface $policy): self
    {
        $this->retryPolicy = $policy;

        return $this;
    }

    /** {@inheritDoc} */
    public function getRetryPolicy(): RetryPolicyInterface
    {
        return $this->retryPolicy;
    }

    /**
     * {@inheritDoc}
     *
     * @param array<string, mixed> $context
     */
    public function setLogContext(array $context): self
    {
        unset($context['correlation_id'], $context['host'], $context['port']);
        $this->logContext = $context;

        return $this;
    }

    /**
     * {@inheritDoc}
     *
     * @return array<string, mixed>
     */
    public function getLogContext(): array
    {
        return $this->logContext;
    }

    /**
     * Best-effort close on garbage collection so a forgotten client
     * doesn't leak the underlying SSH session.
     */
    public function __destruct()
    {
        $this->close();
    }

    /** {@inheritDoc} */
    public function enableFileSizeVerification(): self
    {
        $this->fileSizeVerificationEnabled = true;

        return $this;
    }

    /** {@inheritDoc} */
    public function disableFileSizeVerification(): self
    {
        $this->fileSizeVerificationEnabled = false;

        return $this;
    }

    /** {@inheritDoc} */
    public function enableAtomicUploads(): self
    {
        $this->atomicUploads = true;

        return $this;
    }

    /** {@inheritDoc} */
    public function disableAtomicUploads(): self
    {
        $this->atomicUploads = false;

        return $this;
    }

    /** {@inheritDoc} */
    public function getAtomicUploads(): bool
    {
        return $this->atomicUploads;
    }

    /** {@inheritDoc} */
    public function setChunkSize(int $bytes): self
    {
        if ($bytes < 1) {
            throw new ConfigurationException(\sprintf('chunkSize must be >= 1; got %d.', $bytes));
        }
        $this->chunkSize = $bytes;

        return $this;
    }

    /** {@inheritDoc} */
    public function getChunkSize(): int
    {
        return $this->chunkSize;
    }

    /** {@inheritDoc} */
    public function setCredentials(CredentialsInterface $credentials): self
    {
        $this->credentials = $credentials;
        // Eagerly clear any loader so subsequent connect() uses the
        // explicit credentials. Keeping both around would be ambiguous.
        $this->credentialsLoader = null;

        return $this;
    }

    /** {@inheritDoc} */
    public function getCredentials(): ?CredentialsInterface
    {
        return $this->credentials;
    }

    /**
     * Install a {@see CredentialsLoaderInterface} that resolves credentials
     * per-host at connect-time. Mutually exclusive with
     * {@see setCredentials()} — setting one clears the other.
     */
    public function setCredentialsLoader(CredentialsLoaderInterface $loader): self
    {
        $this->credentialsLoader = $loader;
        $this->credentials = null;

        return $this;
    }

    /** {@inheritDoc} */
    public function getCredentialsLoader(): ?CredentialsLoaderInterface
    {
        return $this->credentialsLoader;
    }

    /**
     * Install a per-host {@see AuthFailureRateLimiter} that sleeps the
     * caller after repeated authentication failures, complementing
     * server-side lockout protections (fail2ban / sshguard). Pass `null`
     * to disable. Off by default — opt in when the deployment has caller
     * code that might retry connect() on auth errors.
     */
    public function setAuthFailureRateLimiter(?AuthFailureRateLimiter $limiter): self
    {
        $this->authRateLimiter = $limiter;

        return $this;
    }

    /** {@inheritDoc} */
    public function getAuthFailureRateLimiter(): ?AuthFailureRateLimiter
    {
        return $this->authRateLimiter;
    }

    /**
     * {@inheritDoc}
     *
     * Stock implementations live in `src/Checksum/`:
     *  - {@see \IDCT\Networking\Ssh\Checksum\ShellSumRemoteHasher} (ssh2_exec sha256sum)
     *  - {@see \IDCT\Networking\Ssh\Checksum\RedownloadRemoteHasher} (re-fetch + hash)
     */
    public function setRemoteHasher(?RemoteHasherInterface $hasher): self
    {
        $this->remoteHasher = $hasher;

        return $this;
    }

    /** {@inheritDoc} */
    public function getRemoteHasher(): ?RemoteHasherInterface
    {
        return $this->remoteHasher;
    }

    /** {@inheritDoc} */
    public function setLocalPrefix(string $prefix): self
    {
        $this->localPrefix = $prefix;

        return $this;
    }

    /** {@inheritDoc} */
    public function getLocalPrefix(): string
    {
        return $this->localPrefix;
    }

    /** {@inheritDoc} */
    public function setRemotePrefix(string $prefix): self
    {
        $this->remotePrefix = $prefix;

        return $this;
    }

    /** {@inheritDoc} */
    public function getRemotePrefix(): string
    {
        return $this->remotePrefix;
    }

    /** {@inheritDoc} */
    public function connect(
        string $host,
        int $port = 22,
        ?int $timeoutSeconds = null,
        ?string $expectedFingerprint = null,
        FingerprintAlgorithm $fingerprintAlgorithm = FingerprintAlgorithm::Sha256,
        FingerprintEncoding $fingerprintEncoding = FingerprintEncoding::Hex,
        ?string $knownHostsFile = null,
        UnknownHostPolicy $onUnknownHost = UnknownHostPolicy::Reject,
        ?SecurityProfile $securityProfile = null,
    ): self {
        // Resolve credentials: a loader (if installed) wins, so credentials
        // get re-resolved per connect() — necessary for callers connecting to
        // different hosts on the same client instance, or for loaders that
        // rotate tokens. Otherwise fall back to whatever setCredentials() set.
        if ($this->credentialsLoader !== null) {
            $this->credentials = $this->credentialsLoader->load($host);
        }
        if ($this->credentials === null) {
            throw new ConfigurationException(
                'Credentials must be set before calling connect(); use setCredentials() or setCredentialsLoader().',
            );
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
        $this->knownHostsFile = $knownHostsFile;
        $this->onUnknownHost = $onUnknownHost;
        $this->securityProfile = $securityProfile;

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
            TcpProbe::check($host, $port, $this->timeoutSeconds);
        }

        $methods = $this->securityProfile?->toMethodsArray();
        if ($this->securityProfile === SecurityProfile::Legacy) {
            $this->log('notice', 'SSH SecurityProfile::Legacy in use — weak algorithms permitted', [
                'profile' => 'Legacy',
            ]);
        }

        $session = $this->ssh2->connect($host, $port, $methods);
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

        if ($this->knownHostsFile !== null) {
            $this->verifyAgainstKnownHosts($session, $host, $port);
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

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
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

    /**
     * The actual download body, wrapped by {@see download()} in the retry
     * loop. Opens the remote SFTP stream, copies into `$localFileName`
     * (or the remote basename under `$localPrefix`), and optionally
     * verifies the size + checksum.
     *
     * Returns `true` so the closure passed to {@see retry()} has a value.
     */
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
                    StreamCopier::copy(
                        $remoteStream,
                        $localStream,
                        $this->chunkSize,
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
            $this->verifyRemoteHash($savePath, $remoteFilePath);
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

    /** {@inheritDoc} */
    public function upload(
        string $localFilePath,
        ?string $remoteFileName = null,
        ?ProgressListenerInterface $progress = null,
    ): self {
        $this->retry('upload', fn(): true => $this->doUpload($localFilePath, $remoteFileName, $progress));

        return $this;
    }

    /**
     * The actual upload body, wrapped by {@see upload()} in the retry loop.
     * Honors {@see $atomicUploads} (writes to `.partial-{uuid}`, then
     * renames onto `$finalPath`); on failure best-effort unlinks the partial
     * and rethrows so {@see retry()} can decide whether to retry.
     */
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
            ? StreamCopier::partialPath($finalPath, 'partial-' . bin2hex(random_bytes(4)))
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
                    StreamCopier::copy(
                        $localStream,
                        $remoteStream,
                        $this->chunkSize,
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
            // Checksum the file at its FINAL path — atomic rename means
            // the partial path is gone by the time we get here.
            $this->verifyRemoteHash($localFilePath, $finalPath);
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

    /** {@inheritDoc} */
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
            ? StreamCopier::partialPath($finalPath, 'partial-' . bin2hex(random_bytes(4)))
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
                $copied = StreamCopier::copy(
                    $stream,
                    $remoteStream,
                    $this->chunkSize,
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
                $copied = StreamCopier::copy(
                    $remoteStream,
                    $stream,
                    $this->chunkSize,
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

    /** {@inheritDoc} */
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

    /**
     * The resume-upload body, wrapped by {@see resumeUpload()} in the
     * retry loop. Auto-detects the partial size when `$offset` is null,
     * appends from there to the deterministic `.{basename}.resume`
     * sibling, and renames onto the final path. Failures leave the
     * partial in place so the next attempt can resume.
     */
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
        $partialPath = StreamCopier::partialPath($finalPath, 'resume');
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
                    StreamCopier::seekOrThrow($localStream, $offset, 'local file', $localFilePath);
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
                        StreamCopier::seekOrThrow($remoteStream, $offset, 'remote partial', $partialPath);
                    }
                    StreamCopier::copy(
                        $localStream,
                        $remoteStream,
                        $this->chunkSize,
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
            $this->verifyRemoteHash($localFilePath, $finalPath);
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

    /** {@inheritDoc} */
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

    /**
     * The resume-download body, wrapped by {@see resumeDownload()} in the
     * retry loop. Auto-detects the local file size when `$offset` is null,
     * seeks the remote stream to that offset, and appends to the local
     * file. No-ops cleanly when the local size already equals the remote
     * size.
     */
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
                    StreamCopier::seekOrThrow($remoteStream, $offset, 'remote stream', $remoteFilePath);
                }

                $localStream = @fopen($savePath, $offset > 0 ? 'ab' : 'wb');
                if ($localStream === false) {
                    throw new TransferException('Unable to open local file for writing: ' . $savePath);
                }

                try {
                    StreamCopier::copy(
                        $remoteStream,
                        $localStream,
                        $this->chunkSize,
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
            $this->verifyRemoteHash($savePath, $remoteFilePath);
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
     * If a {@see RemoteHasherInterface} is installed, hash both sides
     * and throw a {@see TransferException} on mismatch. No-op when no
     * hasher is configured.
     *
     * Called at the end of upload / resumeUpload / download /
     * resumeDownload — after size verification but before progress
     * `completed()`.
     */
    private function verifyRemoteHash(string $localPath, string $remotePath): void
    {
        $hasher = $this->remoteHasher;
        if ($hasher === null) {
            return;
        }
        $algo = $hasher->algorithm();

        try {
            $localHex = @hash_file($algo, $localPath);
        } catch (\ValueError $e) {
            // PHP 8 throws ValueError on unknown algorithm; translate to
            // a TransferException so callers see the library's exception
            // hierarchy rather than a raw VM error.
            throw new TransferException(\sprintf(
                'Checksum verification: hash algorithm "%s" is not supported by PHP — %s.',
                $algo,
                $e->getMessage(),
            ));
        }
        if ($localHex === false) {
            throw new TransferException(\sprintf(
                'Checksum verification: could not hash local file %s with %s.',
                $localPath,
                $algo,
            ));
        }
        $remoteHex = $hasher->hash($this, $remotePath);
        if (! hash_equals(strtolower($localHex), strtolower($remoteHex))) {
            throw new TransferException(\sprintf(
                'Checksum mismatch (%s) for %s: local=%s remote=%s',
                $algo,
                $remotePath,
                $localHex,
                $remoteHex,
            ));
        }
        $this->log('debug', 'Checksum verified', [
            'remote' => $remotePath,
            'algorithm' => $algo,
        ]);
    }

    /** {@inheritDoc} */
    public function scpDownload(string $remoteFilePath, ?string $localFileName = null): self
    {
        PathValidator::validateRemotePath($remoteFilePath);

        $this->retry('scpDownload', fn(): true => $this->doScpDownload($remoteFilePath, $localFileName));

        return $this;
    }

    /**
     * SCP-receive body, wrapped by {@see scpDownload()} in the retry loop.
     * SCP transfers are non-atomic — bytes land at `$savePath` directly.
     */
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

    /** {@inheritDoc} */
    public function scpUpload(string $localFilePath, ?string $remoteFileName = null): self
    {
        $this->retry('scpUpload', fn(): true => $this->doScpUpload($localFilePath, $remoteFileName));

        return $this;
    }

    /**
     * SCP-send body, wrapped by {@see scpUpload()} in the retry loop.
     * SCP transfers are non-atomic — bytes land at the final path in one
     * pass, with fixed-mode 0o644.
     */
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

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
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
     * {@inheritDoc}
     *
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

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
    public function walk(string $remoteDir, SymlinkPolicy $symlinks = SymlinkPolicy::Skip): iterable
    {
        PathValidator::validateRemotePath($remoteDir);
        $sftp = $this->requireSftp(); // surface "not connected" before the generator runs

        $visited = [];
        // Seed the cycle detector with the root dir's inode so a symlink
        // pointing back at the walk's starting point trips the visited
        // check on the first descent attempt rather than re-entering.
        if ($symlinks === SymlinkPolicy::Follow) {
            $rootStat = $this->ssh2->sftpStat($sftp, rtrim($remoteDir, '/'));
            if ($rootStat !== false && isset($rootStat['dev'], $rootStat['ino'])) {
                $visited[$rootStat['dev'] . ':' . $rootStat['ino']] = true;
            }
        }

        return $this->walkInternal($remoteDir, $symlinks, $visited);
    }

    /**
     * {@inheritDoc}
     *
     * Walks the local tree top-down (so dirs land before the files
     * inside them), `mkdir`s each subdir on the remote, and delegates
     * per-file transfer to {@see upload()} — atomic write, retry,
     * file-size verification, and progress emission all apply per file.
     */
    public function uploadDirectory(
        string $localDir,
        string $remoteDir,
        bool $createRemoteDir = true,
        ?ProgressListenerInterface $progress = null,
        ConflictPolicy $onConflict = ConflictPolicy::Overwrite,
        SymlinkPolicy $symlinks = SymlinkPolicy::Skip,
        bool $bestEffort = false,
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

        $localRoot = rtrim($localDir, \DIRECTORY_SEPARATOR);

        $files = 0;
        $bytes = 0;
        $skipped = [];
        $failures = [];
        $visited = [];
        // Seed cycle detector with the local root inode so a symlink
        // pointing back at the upload's starting point trips the visited
        // check before we recurse into it. Without this seed, iteration
        // order determines whether real files end up under the cycle
        // branch (e.g. /remote/loop/inner/real.txt) instead of the
        // intended /remote/inner/real.txt.
        if ($symlinks === SymlinkPolicy::Follow) {
            $rootStat = @stat($localRoot);
            if ($rootStat !== false) {
                $visited[$rootStat['dev'] . ':' . $rootStat['ino']] = true;
            }
        }

        $this->log('debug', 'SFTP upload directory start', [
            'local' => $localRoot,
            'remote' => $remoteDir,
            'conflict' => $onConflict->name,
            'symlinks' => $symlinks->name,
            'best_effort' => $bestEffort,
        ]);

        $this->uploadDirectoryRecurse(
            $localRoot,
            $remoteDir,
            $progress,
            $onConflict,
            $symlinks,
            $bestEffort,
            $visited,
            $files,
            $bytes,
            $skipped,
            $failures,
        );

        $this->log('info', 'SFTP upload directory ok', [
            'local' => $localRoot,
            'remote' => $remoteDir,
            'files' => $files,
            'bytes' => $bytes,
            'skipped' => \count($skipped),
            'failures' => \count($failures),
        ]);

        return new UploadResult(max(0, $files), max(0, $bytes), $skipped, $failures);
    }

    /**
     * Manual top-down recursion for uploadDirectory. Replaces the
     * RecursiveDirectoryIterator path because the iterator can't
     * cleanly express the (a) conflict-policy probe, (b) symlink-
     * follow with inode cycle detection, and (c) best-effort
     * collection without each branch fighting the iterator's flags.
     *
     * @param array<string, true> $visited inode-set keyed by 'dev:ino'
     * @param-out array<string, true> $visited
     * @param list<string> $skipped
     * @param-out list<string> $skipped
     * @param list<DirectoryFailure> $failures
     * @param-out list<DirectoryFailure> $failures
     */
    private function uploadDirectoryRecurse(
        string $localDir,
        string $remoteDir,
        ?ProgressListenerInterface $progress,
        ConflictPolicy $onConflict,
        SymlinkPolicy $symlinks,
        bool $bestEffort,
        array &$visited,
        int &$files,
        int &$bytes,
        array &$skipped,
        array &$failures,
    ): void {
        $sftp = $this->requireSftp();

        $iter = new \DirectoryIterator($localDir);
        foreach ($iter as $info) {
            if ($info->isDot()) {
                continue;
            }
            $localPath = $info->getPathname();
            $remotePath = $remoteDir . '/' . str_replace(\DIRECTORY_SEPARATOR, '/', $info->getBasename());
            $isLink = $info->isLink();

            // Symlink policy gate — Skip records and bails; Follow lets
            // the regular flow handle the (resolved) entry but only
            // after cycle detection.
            if ($isLink && $symlinks === SymlinkPolicy::Skip) {
                $skipped[] = $localPath;
                $this->log('debug', 'SFTP upload directory skipped symlink', ['local' => $localPath]);

                continue;
            }

            // For follow mode, classify by RESOLVED target (isDir/isFile
            // on a SplFileInfo of a symlink follows the link).
            if ($info->isDir()) {
                // Inode cycle detection for symlinked dirs only — regular
                // dirs in a posix tree never form cycles unless someone's
                // done something exotic with bind mounts; we still
                // tolerate it because the cost is one stat() per dir.
                if ($symlinks === SymlinkPolicy::Follow) {
                    $st = @stat($localPath);
                    if ($st !== false) {
                        $key = $st['dev'] . ':' . $st['ino'];
                        if (isset($visited[$key])) {
                            $skipped[] = $localPath . ' (cycle)';
                            $this->log('debug', 'SFTP upload directory skipped cycle', [
                                'local' => $localPath,
                            ]);

                            continue;
                        }
                        $visited[$key] = true;
                    }
                }

                try {
                    if ($this->ssh2->sftpStat($sftp, $remotePath) === false
                        && ! $this->ssh2->sftpMkdir($sftp, $remotePath, 0o755, false)) {
                        throw new RemoteFilesystemException(
                            'uploadDirectory(): unable to create remote directory ' . $remotePath,
                        );
                    }
                    $this->uploadDirectoryRecurse(
                        $localPath,
                        $remotePath,
                        $progress,
                        $onConflict,
                        $symlinks,
                        $bestEffort,
                        $visited,
                        $files,
                        $bytes,
                        $skipped,
                        $failures,
                    );
                } catch (\Throwable $e) {
                    if (! $bestEffort) {
                        throw $e;
                    }
                    $failures[] = new DirectoryFailure($localPath, $e->getMessage(), $e::class);
                }

                continue;
            }

            // File (or symlink-to-file under Follow): apply conflict
            // policy first, then delegate to upload().
            try {
                if ($onConflict !== ConflictPolicy::Overwrite
                    && $this->ssh2->sftpStat($sftp, $remotePath) !== false) {
                    if ($onConflict === ConflictPolicy::Skip) {
                        $skipped[] = $localPath;
                        $this->log('debug', 'SFTP upload directory skipped existing', [
                            'local' => $localPath,
                            'remote' => $remotePath,
                        ]);

                        continue;
                    }

                    // ConflictPolicy::Fail
                    throw new RemoteFilesystemException(
                        'uploadDirectory(): refusing to overwrite existing remote file ' . $remotePath
                        . ' (ConflictPolicy::Fail)',
                    );
                }
                $this->upload($localPath, $remotePath, $progress);
                $files++;
                $bytes += max(0, (int) $info->getSize());
            } catch (\Throwable $e) {
                if (! $bestEffort) {
                    throw $e;
                }
                $failures[] = new DirectoryFailure($localPath, $e->getMessage(), $e::class);
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * Walks the remote tree top-down, `mkdir`s each subdir locally,
     * and delegates per-file transfer to {@see download()}.
     */
    public function downloadDirectory(
        string $remoteDir,
        string $localDir,
        ?ProgressListenerInterface $progress = null,
        ConflictPolicy $onConflict = ConflictPolicy::Overwrite,
        SymlinkPolicy $symlinks = SymlinkPolicy::Skip,
        bool $bestEffort = false,
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
        $failures = [];

        $this->log('debug', 'SFTP download directory start', [
            'remote' => $remoteDir,
            'local' => $localDir,
            'conflict' => $onConflict->name,
            'symlinks' => $symlinks->name,
            'best_effort' => $bestEffort,
        ]);

        $this->downloadDirectoryRecurse(
            $remoteDir,
            $localDir,
            $progress,
            $onConflict,
            $symlinks,
            $bestEffort,
            $filesTransferred,
            $bytesTransferred,
            $skipped,
            $failures,
        );

        $this->log('info', 'SFTP download directory ok', [
            'remote' => $remoteDir,
            'local' => $localDir,
            'files' => $filesTransferred,
            'bytes' => $bytesTransferred,
            'skipped' => \count($skipped),
            'failures' => \count($failures),
        ]);

        // Clamp on the boundary: the helper widens int<0, max> back to
        // plain int through the recursive by-ref parameter, but the
        // counters are only ever incremented so the runtime invariant
        // holds. max(0, ...) re-establishes the type for the value object.
        return new DownloadResult(max(0, $filesTransferred), max(0, $bytesTransferred), $skipped, $failures);
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
     * Under {@see SymlinkPolicy::Follow}, the `$visited` inode set is
     * shared across the whole walk (by reference) so a symlink that
     * cycles back to an ancestor directory is dropped on the second
     * visit rather than re-entered.
     *
     * @param array<string, true> $visited Inode-set keyed by `dev:ino`.
     *
     * @return \Generator<RemoteEntry>
     */
    private function walkInternal(string $remoteDir, SymlinkPolicy $symlinks, array &$visited): \Generator
    {
        $remoteDir = rtrim($remoteDir, '/');
        $sftp = $this->requireSftp();

        foreach ($this->getFileList($remoteDir) as $name) {
            $path = $remoteDir . '/' . $name;
            $type = $this->entryType($path);

            // Symlink + Follow: resolve via sftpStat (follows the link),
            // re-classify by the target's mode bits, descend through the
            // link path when the target is a directory.
            if ($type === EntryType::Symlink && $symlinks === SymlinkPolicy::Follow) {
                $targetStat = $this->ssh2->sftpStat($sftp, $path);
                if ($targetStat === false || ! isset($targetStat['mode'])) {
                    // Dangling or unreadable target — preserve the symlink
                    // entry so the caller can see what was there.
                    yield new RemoteEntry($path, EntryType::Symlink, null);

                    continue;
                }

                $targetType = match ($targetStat['mode'] & 0o170000) {
                    0o040000 => EntryType::Directory,
                    0o100000 => EntryType::File,
                    default => EntryType::Other,
                };

                if ($targetType === EntryType::Directory) {
                    // Inode cycle detection. sftpStat returns POSIX
                    // dev+ino on every server we ship against; absence
                    // is treated as "stat lied to us" — fall back to
                    // skipping rather than re-entering and risking
                    // unbounded recursion.
                    if (isset($targetStat['dev'], $targetStat['ino'])) {
                        $key = $targetStat['dev'] . ':' . $targetStat['ino'];
                        if (isset($visited[$key])) {
                            $this->log('debug', 'SFTP walk skipped symlink cycle', [
                                'remote' => $path,
                            ]);

                            continue;
                        }
                        $visited[$key] = true;
                    } else {
                        $this->log('debug', 'SFTP walk skipped symlink with unreadable inode', [
                            'remote' => $path,
                        ]);

                        continue;
                    }

                    yield from $this->walkInternal($path, $symlinks, $visited);
                    yield new RemoteEntry($path, EntryType::Directory, null);

                    continue;
                }

                if ($targetType === EntryType::File) {
                    $size = isset($targetStat['size']) ? max(0, $targetStat['size']) : null;
                    yield new RemoteEntry($path, EntryType::File, $size);

                    continue;
                }

                // Socket / FIFO / device behind a symlink — preserve the
                // symlink classification rather than collapsing to Other.
                yield new RemoteEntry($path, EntryType::Symlink, null);

                continue;
            }

            // Default path: directory recursion, symlink-as-symlink under
            // Skip mode, files yielded with size, everything else yielded
            // with no size.
            if ($type === EntryType::Directory) {
                yield from $this->walkInternal($path, $symlinks, $visited);
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
     * @param list<DirectoryFailure> $failures
     * @param-out list<DirectoryFailure> $failures
     */
    private function downloadDirectoryRecurse(
        string $remoteDir,
        string $localDir,
        ?ProgressListenerInterface $progress,
        ConflictPolicy $onConflict,
        SymlinkPolicy $symlinks,
        bool $bestEffort,
        int &$filesTransferred,
        int &$bytesTransferred,
        array &$skipped,
        array &$failures,
    ): void {
        foreach ($this->getFileList($remoteDir) as $name) {
            $remotePath = $remoteDir . '/' . $name;
            $localPath = $localDir . '/' . $name;
            $type = $this->entryType($remotePath);

            // Symlink / device / FIFO entries: skip by default; under
            // Follow we'd need lstat-then-stat dance — for the first
            // cut, document Follow as "no-op on remote side" because
            // libssh2's per-link target resolution isn't exposed by
            // ext-ssh2's url_stat consistently across versions.
            if ($type === EntryType::Symlink || $type === EntryType::Other) {
                $skipped[] = $remotePath;
                if ($type === EntryType::Symlink && $symlinks === SymlinkPolicy::Follow) {
                    // Record the gap loudly so the caller knows why their
                    // symlink got skipped despite Follow being requested.
                    $this->log('notice', 'SFTP download directory cannot follow remote symlink', [
                        'remote' => $remotePath,
                        'reason' => 'remote-side symlink-follow deferred — see CHANGELOG',
                    ]);
                }

                continue;
            }
            if ($type === EntryType::Directory) {
                try {
                    if (! is_dir($localPath) && ! @mkdir($localPath, 0o755, true) && ! is_dir($localPath)) {
                        throw new RemoteFilesystemException(
                            'downloadDirectory(): unable to create local directory ' . $localPath,
                        );
                    }
                    $this->downloadDirectoryRecurse(
                        $remotePath,
                        $localPath,
                        $progress,
                        $onConflict,
                        $symlinks,
                        $bestEffort,
                        $filesTransferred,
                        $bytesTransferred,
                        $skipped,
                        $failures,
                    );
                } catch (\Throwable $e) {
                    if (! $bestEffort) {
                        throw $e;
                    }
                    $failures[] = new DirectoryFailure($remotePath, $e->getMessage(), $e::class);
                }

                continue;
            }

            // EntryType::File
            try {
                if ($onConflict !== ConflictPolicy::Overwrite && is_file($localPath)) {
                    if ($onConflict === ConflictPolicy::Skip) {
                        $skipped[] = $remotePath;

                        continue;
                    }

                    // ConflictPolicy::Fail — local file is the caller's
                    // problem, not the server's, hence ConfigurationException
                    // rather than RemoteFilesystemException.
                    throw new ConfigurationException(
                        'downloadDirectory(): refusing to overwrite existing local file ' . $localPath
                        . ' (ConflictPolicy::Fail)',
                    );
                }
                $this->download($remotePath, $localPath, $progress);
                $filesTransferred++;
                $size = $this->statSize($remotePath);
                if ($size !== null) {
                    $bytesTransferred += $size;
                }
            } catch (\Throwable $e) {
                if (! $bestEffort) {
                    throw $e;
                }
                $failures[] = new DirectoryFailure($remotePath, $e->getMessage(), $e::class);
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

    /** {@inheritDoc} */
    public function fileExists(string $path): bool
    {
        PathValidator::validateRemotePath($path);

        $sftp = $this->requireSftp();
        $uri = $this->ssh2->sftpStreamUri($sftp, $path);
        clearstatcache(true, $uri);

        return @file_exists($uri);
    }

    /** {@inheritDoc} */
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
     * Wrap an operation in the configured retry policy + lazy reconnect.
     *
     * The "is this retryable?" decision is delegated to
     * {@see RetryClassifier::isRetryable()} — kept stateless and reusable.
     * The loop itself stays here because lazy reconnect needs the live
     * session state (`$this->sshSession`, `$this->sftp`,
     * `$this->doConnect()`) that a pure-static collaborator can't carry.
     *
     * Decision flow:
     * - If $operation throws an exception classified as never-retry
     *   (auth, config, path validation), propagate immediately.
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
                if (! RetryClassifier::isRetryable($e)) {
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
     * Wraps {@see AuthDispatcher::dispatch()} with rate-limiter calls,
     * logging, and the typed `AuthenticationException` on rejection.
     * The dispatcher owns the ssh2_auth_* call selection; this method
     * owns the side effects.
     *
     * @param resource $session
     */
    private function authorize(mixed $session, CredentialsInterface $credentials): void
    {
        $username = $credentials->getUsername();
        $mode = $credentials->getMode();
        $host = $this->host ?? '';
        $port = $this->port ?? 0;

        // Sleep before the auth call when the limiter says so — guards
        // against accidental account lockout when the CALLER retries.
        $this->authRateLimiter?->beforeAuth($host, $port, $username);

        $ok = AuthDispatcher::dispatch($session, $credentials, $this->ssh2);

        if (! $ok) {
            $this->authRateLimiter?->recordFailure($host, $port, $username);
            $this->log('notice', 'SSH authentication rejected', [
                'user' => $username,
                'mode' => $mode->name,
            ]);

            throw new AuthenticationException(
                'SSH authentication failed for user "' . $username . '" using ' . $mode->name . ' mode.',
            );
        }

        $this->authRateLimiter?->recordSuccess($host, $port, $username);
        $this->log('info', 'SSH authentication ok', [
            'user' => $username,
            'mode' => $mode->name,
        ]);
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

    /**
     * Thin wrapper around {@see HostKeyVerifier::verify()}. The verifier
     * decides Trusted / TofuAppended / throws; the client owns logging
     * and session cleanup. Caller-side gate (`knownHostsFile !== null`)
     * is enforced in {@see doConnect()}, so `$this->knownHostsFile` is
     * non-null here.
     *
     * @param resource $session
     */
    private function verifyAgainstKnownHosts(mixed $session, string $host, int $port): void
    {
        $file = (string) $this->knownHostsFile;

        try {
            $result = HostKeyVerifier::verify(
                $session,
                $host,
                $port,
                $file,
                $this->onUnknownHost,
                $this->ssh2,
            );
        } catch (ConnectionException $e) {
            $this->ssh2->disconnect($session);
            $msg = $e->getMessage();
            // Map the verifier's specific failure phrasings back to the
            // log levels the operations matrix prescribes (`notice` for
            // policy-rejected unknown hosts, `error` for everything else).
            if (str_starts_with($msg, 'Unknown host')) {
                $this->log('notice', 'Known-hosts: unknown host rejected', [
                    'file' => $file,
                ]);
            } elseif (str_starts_with($msg, 'Known-hosts mismatch')) {
                $this->log('error', 'Known-hosts: host key mismatch (possible MITM)', [
                    'file' => $file,
                ]);
            } else {
                $this->log('error', 'Known-hosts: host key fingerprint unreadable');
            }

            throw $e;
        }

        if ($result->tofuAppended) {
            $this->log('info', 'Known-hosts: TOFU entry appended', [
                'file' => $file,
                'fingerprint' => $result->fingerprint,
            ]);

            return;
        }

        $this->log('debug', 'Known-hosts: host key trusted', ['file' => $file]);
    }

}
