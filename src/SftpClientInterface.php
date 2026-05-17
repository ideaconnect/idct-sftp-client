<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh;

use IDCT\Networking\Ssh\Auth\CredentialsInterface;
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
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;

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
    public function setCredentials(CredentialsInterface $credentials): self;

    public function getCredentials(): ?CredentialsInterface;

    public function setLocalPrefix(string $prefix): self;

    public function getLocalPrefix(): string;

    public function setRemotePrefix(string $prefix): self;

    public function getRemotePrefix(): string;

    public function enableFileSizeVerification(): self;

    public function disableFileSizeVerification(): self;

    /**
     * Atomic uploads: write to a hidden `.partial-{uuid}` sibling first, then
     * rename onto the final path. Enabled by default; disable for servers
     * that reject overwrite-on-rename. SCP transfers are never atomic
     * regardless of this flag — SCP is a one-shot push with no rename step.
     */
    public function enableAtomicUploads(): self;

    public function disableAtomicUploads(): self;

    public function getAtomicUploads(): bool;

    /**
     * Bytes per fread/fwrite during stream copies. Defaults to 1 MiB; 8 MiB
     * can be dramatically faster on high-latency / high-bandwidth links.
     * Must be at least 1.
     *
     * @throws ConfigurationException
     */
    public function setChunkSize(int $bytes): self;

    public function getChunkSize(): int;

    /**
     * @throws ConfigurationException credentials not set, fingerprint mismatch
     * @throws ConnectionException tcp/handshake failure
     * @throws AuthenticationException auth rejected
     */
    public function connect(
        string $host,
        int $port = 22,
        ?int $timeoutSeconds = null,
        ?string $expectedFingerprint = null,
        FingerprintAlgorithm $fingerprintAlgorithm = FingerprintAlgorithm::Sha256,
        FingerprintEncoding $fingerprintEncoding = FingerprintEncoding::Hex,
    ): self;

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
