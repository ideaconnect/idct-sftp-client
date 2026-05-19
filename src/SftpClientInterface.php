<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh;

use IDCT\Networking\Ssh\Auth\AuthFailureRateLimiter;
use IDCT\Networking\Ssh\Auth\CredentialsInterface;
use IDCT\Networking\Ssh\Auth\CredentialsLoaderInterface;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;
use IDCT\Networking\Ssh\Security\SecurityProfile;

/**
 * Public contract for the SFTP client.
 *
 * Exists so callers can swap in a fake / in-memory implementation in tests,
 * or bind a different transport (e.g., a phpseclib backend) without
 * rewriting consumer code. Every method documented to throw raises a
 * {@see SshException} subclass; `catch (SshException $e)` grabs anything
 * this library can raise.
 */
interface SftpClientInterface
{
    /**
     * Install a static credentials object used for every {@see connect()}
     * call. Mutually exclusive with {@see setCredentialsLoader()}: setting
     * one clears the other.
     */
    public function setCredentials(CredentialsInterface $credentials): self;

    /**
     * Return the static credentials installed via {@see setCredentials()},
     * or `null` if none are set (either because a loader is in use or
     * because no credentials have been configured yet).
     */
    public function getCredentials(): ?CredentialsInterface;

    /**
     * Per-host credentials resolution. Mutually exclusive with
     * {@see setCredentials()}: setting one clears the other. Use this
     * to plug Vault / Secrets Manager / etc. without the client
     * knowing about the source.
     */
    public function setCredentialsLoader(CredentialsLoaderInterface $loader): self;

    /**
     * Return the credentials loader installed via
     * {@see setCredentialsLoader()}, or `null` if none is set (either
     * because static credentials are in use or because nothing has
     * been configured yet).
     */
    public function getCredentialsLoader(): ?CredentialsLoaderInterface;

    /**
     * Optional in-process auth-failure backoff. Pass `null` to disable.
     */
    public function setAuthFailureRateLimiter(?AuthFailureRateLimiter $limiter): self;

    /**
     * Return the auth-failure rate limiter installed via
     * {@see setAuthFailureRateLimiter()}, or `null` if disabled.
     */
    public function getAuthFailureRateLimiter(): ?AuthFailureRateLimiter;

    /**
     * Prefix prepended to every LOCAL path passed to upload / download /
     * directory helpers. Absolute paths (those starting with `/`) bypass
     * the prefix. Pass `''` to disable.
     */
    public function setLocalPrefix(string $prefix): self;

    /**
     * Return the current local path prefix, or `''` if none is set.
     */
    public function getLocalPrefix(): string;

    /**
     * Prefix prepended to every REMOTE path passed to transfer / directory
     * helpers. Absolute paths (those starting with `/`) bypass the prefix.
     * Pass `''` to disable.
     */
    public function setRemotePrefix(string $prefix): self;

    /**
     * Return the current remote path prefix, or `''` if none is set.
     */
    public function getRemotePrefix(): string;

    /**
     * Enable post-transfer size verification. After every upload and
     * download the client stats both ends and raises
     * {@see TransferException} if the byte counts differ. Costs one extra
     * stat round-trip per file; on by default.
     */
    public function enableFileSizeVerification(): self;

    /**
     * Disable post-transfer size verification. Use when the remote
     * filesystem is known to misreport sizes (some FUSE backings, certain
     * S3 gateways) or when the overhead matters more than the safety net.
     */
    public function disableFileSizeVerification(): self;

    /**
     * Atomic uploads: write to a hidden `.partial-{uuid}` sibling first, then
     * rename onto the final path. Enabled by default; disable for servers
     * that reject overwrite-on-rename. SCP transfers are never atomic
     * regardless of this flag — SCP is a one-shot push with no rename step.
     */
    public function enableAtomicUploads(): self;

    /**
     * Disable atomic uploads — bytes go straight to the final remote path
     * with no `.partial` sibling. Required for servers that reject overwrite
     * via rename (some legacy SFTP daemons). A crashed upload under this
     * mode leaves a truncated file at the destination.
     */
    public function disableAtomicUploads(): self;

    /**
     * Return whether atomic uploads are currently enabled. Default: true.
     */
    public function getAtomicUploads(): bool;

    /**
     * Bytes per fread/fwrite during stream copies. Defaults to 1 MiB; 8 MiB
     * can be dramatically faster on high-latency / high-bandwidth links.
     * Must be at least 1.
     *
     * @throws ConfigurationException
     */
    public function setChunkSize(int $bytes): self;

    /**
     * Return the current stream-copy chunk size in bytes. Default: 1 MiB.
     */
    public function getChunkSize(): int;

    /**
     * @param string|null $knownHostsFile When set, the server's host key is
     *     verified against this file (OpenSSH `known_hosts` format, plus the
     *     library's own `sha1-fpr` TOFU entries). Mismatch always raises
     *     {@see ConnectionException}; unknown hosts follow `$onUnknownHost`.
     * @param UnknownHostPolicy $onUnknownHost What to do when the host is
     *     not in `$knownHostsFile`. Default `Reject` raises; `TrustOnFirstUse`
     *     appends the new fingerprint and proceeds.
     * @param SecurityProfile|null $securityProfile Cipher / MAC / KEX /
     *     host-key allow-list preset. `null` (default) and
     *     {@see SecurityProfile::Compatible} both leave the libssh2 defaults
     *     untouched; {@see SecurityProfile::Modern} restricts to
     *     post-2014 algorithms; {@see SecurityProfile::Legacy} permits weak
     *     algorithms (logged at notice level).
     *
     * @throws ConfigurationException credentials not set, fingerprint mismatch
     * @throws ConnectionException tcp/handshake failure, known-hosts mismatch, unknown host under Reject policy
     * @throws AuthenticationException auth rejected
     */
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
    ): self;

    /**
     * Tear down the SSH session and release the underlying SFTP handle.
     * Idempotent — safe to call on a never-connected or already-closed
     * client. After close() the next transfer call will lazily reconnect
     * using the stored credentials.
     */
    public function close(): self;

    /**
     * Cheap liveness probe — stat the remote root via SFTP. Useful as a
     * keepalive or to detect a session that died between operations (the
     * client uses it internally for lazy reconnect; callers can use it for
     * application-level health checks).
     *
     * Returns false on any failure (no session, stat denied, network error)
     * without throwing — by contract this method NEVER raises.
     */
    public function ping(): bool;

    /**
     * Install a retry policy used to wrap connect / upload / download /
     * scpUpload / scpDownload. Default is
     * {@see ExponentialBackoffRetryPolicy} with sensible defaults; pass
     * {@see NoRetryPolicy} to opt out of automatic retries entirely.
     */
    public function setRetryPolicy(RetryPolicyInterface $policy): self;

    /**
     * Return the active retry policy. Always non-null — defaults to
     * {@see ExponentialBackoffRetryPolicy} when none was installed.
     */
    public function getRetryPolicy(): RetryPolicyInterface;

    /** @throws TransferException */
    public function download(
        string $remoteFilePath,
        ?string $localFileName = null,
        ?ProgressListenerInterface $progress = null,
    ): self;

    /**
     * Resume an interrupted download by appending to an existing local file.
     * If `$offset` is null, the client stats the local file and resumes from
     * its current size; if the local file is missing or empty, this behaves
     * as a fresh download.
     *
     * No-op (and returns successfully) when the local size already matches
     * the remote size — safe to call after a previous successful resume.
     *
     * @throws TransferException stream copy / open / seek failed
     * @throws ConfigurationException negative offset, or offset beyond the remote file
     */
    public function resumeDownload(
        string $remoteFilePath,
        string $localFileName,
        ?int $offset = null,
        ?ProgressListenerInterface $progress = null,
    ): self;

    /** @throws TransferException */
    public function upload(
        string $localFilePath,
        ?string $remoteFileName = null,
        ?ProgressListenerInterface $progress = null,
    ): self;

    /**
     * Resume an interrupted upload by appending to a deterministic
     * `.{basename}.resume` sibling. If `$offset` is null, the client stats
     * the partial and resumes from its current size — pass an explicit
     * offset only when you have authoritative external knowledge.
     *
     * Failures preserve the partial so the next call can pick up where this
     * one left off (contrast with {@see upload()} atomic mode, which unlinks
     * the partial on failure).
     *
     * @throws TransferException stream copy / open / rename failed
     * @throws ConfigurationException negative offset, or offset beyond the local file
     */
    public function resumeUpload(
        string $localFilePath,
        string $remoteFileName,
        ?int $offset = null,
        ?ProgressListenerInterface $progress = null,
    ): self;

    /**
     * Stream-source upload. Reads from any open PHP resource (file handle,
     * php://memory, S3 stream wrapper, custom user stream) and writes to
     * the remote path. Honors the atomic-uploads flag the same way as
     * {@see upload()}.
     *
     * @param resource $stream
     * @throws TransferException stream copy / open / rename failed
     * @throws ConfigurationException $stream is not a resource, expectedSize mismatch
     */
    public function uploadStream(
        mixed $stream,
        string $remoteFilePath,
        ?int $expectedSize = null,
        ?ProgressListenerInterface $progress = null,
    ): self;

    /**
     * Stream-sink download. Writes the remote file's contents to any open
     * PHP resource. Returns the number of bytes written.
     *
     * @param resource $stream
     * @return int<0, max>
     * @throws TransferException stream copy / open failed
     * @throws ConfigurationException $stream is not a resource
     */
    public function downloadStream(
        string $remoteFilePath,
        mixed $stream,
        ?ProgressListenerInterface $progress = null,
    ): int;

    /** @throws TransferException */
    public function scpDownload(string $remoteFilePath, ?string $localFileName = null): self;

    /** @throws TransferException */
    public function scpUpload(string $localFilePath, ?string $remoteFileName = null): self;

    /** @throws RemoteFilesystemException */
    public function remove(string $remoteFilePath): self;

    /** @throws RemoteFilesystemException */
    public function rename(string $remoteFilePath, string $newRemoteFilePath): self;

    /**
     * @return list<string>
     * @throws RemoteFilesystemException
     */
    public function getFileList(string $remotePath, bool $includeDotEntries = false): array;

    /**
     * @return array<int|string, int> stat()-format array (numeric 0..12 keys plus dev/ino/mode/... string keys)
     * @throws RemoteFilesystemException
     */
    public function stat(string $remotePath): array;

    /** @throws RemoteFilesystemException */
    public function makeDirectory(string $path, int $mode = 0o755, bool $recursive = false): self;

    /** @throws RemoteFilesystemException */
    public function removeDirectory(string $path): self;

    public function fileExists(string $path): bool;

    /**
     * Recursive directory upload. Atomic + retry + progress apply per file
     * (each file goes through {@see upload()}). Symlinks under the local
     * tree are skipped and listed in {@see UploadResult::$skipped}.
     *
     * @throws ConfigurationException missing local dir or invalid remote path
     * @throws TransferException per-file failure
     * @throws RemoteFilesystemException mkdir failed
     */
    public function uploadDirectory(
        string $localDir,
        string $remoteDir,
        bool $createRemoteDir = true,
        ?ProgressListenerInterface $progress = null,
    ): UploadResult;

    /**
     * Recursive directory download. Mirrors {@see uploadDirectory()} in
     * reverse; symlinks on the remote are skipped.
     *
     * @throws ConfigurationException invalid remote path / local dir unwritable
     * @throws TransferException per-file failure
     * @throws RemoteFilesystemException remote stat / readdir failed
     */
    public function downloadDirectory(
        string $remoteDir,
        string $localDir,
        ?ProgressListenerInterface $progress = null,
    ): DownloadResult;

    /**
     * Remove a remote directory and everything beneath it. Recurses
     * post-order (children before parent) so a single permission failure
     * on a leaf surfaces with the offending path, rather than after the
     * whole tree has been partially demolished.
     *
     * @throws RemoteFilesystemException unlink or rmdir refused
     */
    public function removeDirectoryTree(string $remoteDir): self;

    /**
     * Recursively yield every entry under `$remoteDir`, post-order
     * (children before their parent). Symlinks are yielded but their
     * targets are not followed.
     *
     * @return iterable<RemoteEntry>
     * @throws RemoteFilesystemException
     */
    public function walk(string $remoteDir): iterable;
}
