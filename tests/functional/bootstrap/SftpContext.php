<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Functional;

use Behat\Behat\Context\Context;
use Behat\Gherkin\Node\TableNode;
use Behat\Hook\AfterSuite;
use Behat\Hook\BeforeScenario;
use Behat\Hook\BeforeSuite;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Auth\StaticCredentialsLoader;
use IDCT\Networking\Ssh\Checksum\RedownloadRemoteHasher;
use IDCT\Networking\Ssh\Directory\DownloadResult;
use IDCT\Networking\Ssh\Directory\EntryType;
use IDCT\Networking\Ssh\Directory\RemoteEntry;
use IDCT\Networking\Ssh\Directory\UploadResult;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\KnownHosts\UnknownHostPolicy;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Tests\Support\CapturingLogger;
use PHPUnit\Framework\Assert;

/**
 * Behat context that drives a real ext-ssh2 client against one of the
 * dockerised SFTP fixtures started by tests/functional/bin/up.
 *
 * Target is controlled by env vars so the same suite runs against
 * multiple backends:
 *  - SFTP_HOST   (default 127.0.0.1)
 *  - SFTP_PORT   (default 2222 — atmoz/sftp; set 2223 for OpenSSH 9.x)
 *  - SFTP_USER   (default tester)
 *  - SFTP_PASS   (default testerpass)
 *  - SFTP_BASE   (default /data — chroot path on atmoz, ~/data on openssh)
 */
final class SftpContext implements Context
{
    private string $host;
    private int $port;
    private string $user;
    private string $pass;
    private string $remoteBase;

    private ?SftpClient $client = null;
    private string $tmpDir;
    private ?\Throwable $lastError = null;

    /** @var resource|null memory stream used by uploadStream/downloadStream scenarios */
    private mixed $memoryStream = null;

    /** @var resource|null sink stream used by downloadStream scenarios */
    private mixed $sinkStream = null;

    private ?int $lastDownloadBytes = null;
    private ?object $progressRecorder = null;
    private ?UploadResult $lastUploadResult = null;
    private ?DownloadResult $lastDownloadResult = null;
    private ?string $knownHostsPath = null;

    /** Toxiproxy proxy name → admin URL bookkeeping. */
    private ?string $toxiproxyName = null;

    /** Set by the walk-step; consumed by the post-order assertion. */
    /** @var list<RemoteEntry>|null */
    private ?array $lastWalk = null;

    /** Set by the capturing-logger step; consumed by record-context assertions. */
    private ?CapturingLogger $capturingLogger = null;

    #[BeforeSuite]
    public static function startFixture(): void
    {
        // The bin/up script is the documented entrypoint; CI runs it explicitly.
        // We deliberately don't auto-invoke it here so behat works in any environment.
    }

    #[AfterSuite]
    public static function stopFixture(): void
    {
        // Likewise, teardown is the caller's responsibility (CI / bin/down).
    }

    #[BeforeScenario]
    public function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/idct-behat-' . bin2hex(random_bytes(4));
        mkdir($this->tmpDir, 0o755, true);
        $this->host = getenv('SFTP_HOST') !== false ? (string) getenv('SFTP_HOST') : '127.0.0.1';
        $this->port = getenv('SFTP_PORT') !== false ? (int) getenv('SFTP_PORT') : 2222;
        $this->user = getenv('SFTP_USER') !== false ? (string) getenv('SFTP_USER') : 'tester';
        $this->pass = getenv('SFTP_PASS') !== false ? (string) getenv('SFTP_PASS') : 'testerpass';
        $this->remoteBase = getenv('SFTP_BASE') !== false ? (string) getenv('SFTP_BASE') : '/data';
        $this->client = null;
        $this->lastError = null;
        $this->memoryStream = null;
        $this->sinkStream = null;
        $this->lastDownloadBytes = null;
        $this->progressRecorder = null;
        $this->lastUploadResult = null;
        $this->lastDownloadResult = null;
        $this->knownHostsPath = null;
        // Tear down any toxiproxy proxy left over from a previous scenario.
        if ($this->toxiproxyName !== null) {
            $this->toxiproxyDelete($this->toxiproxyName);
            $this->toxiproxyName = null;
        }
    }

    /**
     * @Given /^I have a connected SFTP client$/
     */
    public function iHaveAConnectedSftpClient(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));
        $this->client->connect($this->host, $this->port);
    }

    /**
     * @Given /^the remote directory "([^"]+)" is empty$/
     */
    public function theRemoteDirectoryIsEmpty(string $path): void
    {
        $client = $this->requireClient();

        try {
            foreach ($client->getFileList($path) as $entry) {
                $full = rtrim($path, '/') . '/' . ltrim($entry, '/');

                try {
                    // Try unlink first (regular file or symlink); if the
                    // entry is a directory, fall through to
                    // removeDirectoryTree so nested leftovers from prior
                    // runs get wiped.
                    $client->remove($full);
                } catch (RemoteFilesystemException) {
                    try {
                        $client->removeDirectoryTree($full);
                    } catch (RemoteFilesystemException) {
                        // best effort cleanup
                    }
                }
            }
        } catch (RemoteFilesystemException) {
            // dir might not exist yet — that's fine
        }
    }

    /**
     * @Given /^I have a local file "([^"]+)" containing "([^"]*)"$/
     */
    public function iHaveALocalFile(string $name, string $contents): void
    {
        file_put_contents($this->tmpDir . '/' . $name, $contents);
    }

    /**
     * @When /^I connect with password authentication$/
     */
    public function iConnectWithPassword(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));
        $this->tryConnect();
    }

    /**
     * @When /^I connect with a wrong password$/
     */
    public function iConnectWithWrongPassword(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, 'wrong'));
        $this->tryConnect();
    }

    /**
     * @When /^I connect with public-key authentication$/
     */
    public function iConnectWithPubkey(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPublicKey(
            $this->user,
            __DIR__ . '/../fixtures/keys/id_rsa.pub',
            __DIR__ . '/../fixtures/keys/id_rsa',
        ));
        $this->tryConnect();
    }

    /**
     * @When /^I connect requiring fingerprint "([^"]+)"$/
     */
    public function iConnectWithFingerprint(string $fingerprint): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));

        try {
            $this->client->connect(
                $this->host,
                $this->port,
                null,
                $fingerprint,
                FingerprintAlgorithm::Sha256,
                FingerprintEncoding::Hex,
            );
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I upload "([^"]+)" to "([^"]+)"$/
     */
    public function iUpload(string $localName, string $remotePath): void
    {
        try {
            $this->requireClient()->upload($this->tmpDir . '/' . $localName, $remotePath);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I download "([^"]+)" to "([^"]+)"$/
     */
    public function iDownload(string $remotePath, string $localName): void
    {
        try {
            $this->requireClient()->download($remotePath, $this->tmpDir . '/' . $localName);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I upload "([^"]+)" to "([^"]+)" with atomic mode on$/
     */
    public function iUploadAtomic(string $localName, string $remotePath): void
    {
        // The default client already runs atomic uploads; we re-enable
        // explicitly for documentation purposes and to assert it's the
        // path under test.
        try {
            $this->requireClient()
                ->enableAtomicUploads()
                ->upload($this->tmpDir . '/' . $localName, $remotePath);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Given /^a remote partial "([^"]+)" exists with contents "([^"]*)"$/
     */
    public function aRemotePartialExists(string $remotePath, string $contents): void
    {
        // Pre-stage a partial by uploading then renaming via the client
        // itself — keeps us inside the public API rather than reaching into
        // ssh2_* directly. The seed file is a normal upload to the partial
        // path; the resume flow under test will then rename it.
        $seed = $this->tmpDir . '/__seed_' . bin2hex(random_bytes(3));
        file_put_contents($seed, $contents);
        // disable atomic for this seed upload so we land EXACTLY on
        // $remotePath (a partial-named file), not a partial-of-a-partial.
        $this->requireClient()
            ->disableAtomicUploads()
            ->upload($seed, $remotePath)
            ->enableAtomicUploads();
    }

    /**
     * @Given /^the remote file "([^"]+)" already contains "([^"]*)"$/
     */
    public function seedRemoteFile(string $remotePath, string $contents): void
    {
        // Variation of upload used for "given" preconditions — distinct
        // verb from "Then ... contains" so the scenario reads naturally.
        $seed = $this->tmpDir . '/__seed_' . bin2hex(random_bytes(3));
        file_put_contents($seed, $contents);
        $this->requireClient()
            ->disableAtomicUploads()
            ->upload($seed, $remotePath)
            ->enableAtomicUploads();
    }

    /**
     * @When /^I resume upload of "([^"]+)" to "([^"]+)"$/
     */
    public function iResumeUpload(string $localName, string $remotePath): void
    {
        try {
            $this->requireClient()->resumeUpload($this->tmpDir . '/' . $localName, $remotePath);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I resume download of "([^"]+)" to "([^"]+)"$/
     */
    public function iResumeDownload(string $remotePath, string $localName): void
    {
        try {
            $this->requireClient()->resumeDownload($remotePath, $this->tmpDir . '/' . $localName);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Given /^I have a toxiproxy SFTP proxy named "([^"]+)" to atmoz on port (\d+)$/
     */
    public function iHaveAToxiproxy(string $name, int $listenPort): void
    {
        // Toxiproxy's "upstream" is the host the proxy forwards to. From
        // inside the docker network atmoz is `sftp:22`; the proxy listens
        // on $listenPort on the toxiproxy container, which we publish to
        // 127.0.0.1:22122.
        $this->toxiproxyDelete($name);
        $payload = json_encode([
            'name' => $name,
            'listen' => '0.0.0.0:' . $listenPort,
            'upstream' => 'sftp:22',
            'enabled' => true,
        ], \JSON_THROW_ON_ERROR);
        $this->toxiproxyApi('POST', '/proxies', $payload);
        $this->toxiproxyName = $name;
    }

    /**
     * @Given /^I have a connected SFTP client via the "([^"]+)" proxy$/
     */
    public function iHaveAConnectedClientViaProxy(string $name): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));
        $this->client->connect($this->host, 22122);
    }

    /**
     * @Given /^a (\d+)ms latency toxic is added to "([^"]+)"$/
     */
    public function aLatencyToxic(int $latencyMs, string $name): void
    {
        $payload = json_encode([
            'name' => 'latency-' . $latencyMs,
            'type' => 'latency',
            'stream' => 'downstream',
            'attributes' => ['latency' => $latencyMs],
        ], \JSON_THROW_ON_ERROR);
        $this->toxiproxyApi('POST', '/proxies/' . $name . '/toxics', $payload);
    }

    /**
     * @Given /^a (\d+)-byte-per-second bandwidth toxic is added to "([^"]+)"$/
     */
    public function aBandwidthToxic(int $bytesPerSec, string $name): void
    {
        $payload = json_encode([
            'name' => 'bw-' . $bytesPerSec,
            'type' => 'bandwidth',
            'stream' => 'downstream',
            'attributes' => ['rate' => (int) ($bytesPerSec / 1024)], // toxiproxy expects KB/s
        ], \JSON_THROW_ON_ERROR);
        $this->toxiproxyApi('POST', '/proxies/' . $name . '/toxics', $payload);
    }

    /**
     * Flip the proxy's `enabled` flag. Disabling drops all in-flight
     * connections (the existing SFTP session is reset); re-enabling
     * resumes forwarding so a fresh reconnect can complete.
     *
     * @Given /^the "([^"]+)" proxy is (disabled|enabled)$/
     */
    public function toggleProxyEnabled(string $name, string $state): void
    {
        $payload = json_encode([
            'enabled' => $state === 'enabled',
        ], \JSON_THROW_ON_ERROR);
        $this->toxiproxyApi('POST', '/proxies/' . $name, $payload);
    }

    private function toxiproxyDelete(string $name): void
    {
        // 404 is fine (proxy might not exist). Anything else, ignore for
        // best-effort teardown — the next BeforeScenario will retry.
        @file_get_contents(
            'http://127.0.0.1:8474/proxies/' . $name,
            false,
            stream_context_create(['http' => ['method' => 'DELETE', 'ignore_errors' => true]]),
        );
    }

    private function toxiproxyApi(string $method, string $path, string $body): void
    {
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => "Content-Type: application/json\r\n",
            'content' => $body,
            'ignore_errors' => true,
            'timeout' => 5,
        ]]);
        $resp = @file_get_contents('http://127.0.0.1:8474' . $path, false, $ctx);
        if ($resp === false) {
            throw new \RuntimeException(
                'toxiproxy ' . $method . ' ' . $path . ' failed: ' . ($body ?: '<empty>'),
            );
        }
    }

    /**
     * @Given /^I have an HTTP stream from "([^"]+)"$/
     */
    public function iHaveAnHttpStream(string $url): void
    {
        // fopen on http:// goes through PHP's stream wrapper; the stream
        // is non-seekable, which makes this a stronger test of uploadStream
        // than the php://memory case (memory streams are seekable).
        $stream = @fopen($url, 'rb');
        Assert::assertNotFalse($stream, 'could not open HTTP source ' . $url);
        $this->memoryStream = $stream;
    }

    /**
     * @Given /^I have an in-memory stream containing "([^"]*)"$/
     */
    public function iHaveAnInMemoryStream(string $contents): void
    {
        $stream = fopen('php://memory', 'r+b');
        Assert::assertNotFalse($stream);
        fwrite($stream, $contents);
        rewind($stream);
        $this->memoryStream = $stream;
    }

    /**
     * @When /^I uploadStream to "([^"]+)"$/
     */
    public function iUploadStream(string $remotePath): void
    {
        try {
            $stream = $this->memoryStream;
            Assert::assertNotNull($stream, 'No memory stream prepared — call "I have an in-memory stream" first.');
            $this->requireClient()->uploadStream($stream, $remotePath);
            fclose($stream);
            $this->memoryStream = null;
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I downloadStream "([^"]+)" into a sink$/
     */
    public function iDownloadStreamIntoSink(string $remotePath): void
    {
        try {
            $sink = fopen('php://memory', 'r+b');
            Assert::assertNotFalse($sink);
            $this->sinkStream = $sink;
            $this->lastDownloadBytes = $this->requireClient()->downloadStream($remotePath, $sink);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the sink received "([^"]*)"$/
     */
    public function sinkReceived(string $expected): void
    {
        $sink = $this->sinkStream;
        Assert::assertNotNull($sink);
        rewind($sink);
        $got = stream_get_contents($sink);
        fclose($sink);
        $this->sinkStream = null;
        Assert::assertSame($expected, $got);
    }

    /**
     * @Then /^the reported byte count is (\d+)$/
     */
    public function reportedByteCount(int $expected): void
    {
        Assert::assertSame($expected, $this->lastDownloadBytes);
    }

    /**
     * @Given /^a progress listener is attached$/
     */
    public function progressListenerIsAttached(): void
    {
        $this->progressRecorder = new class implements ProgressListenerInterface {
            /** @var list<array{event: string, args: array<int, mixed>}> */
            public array $events = [];

            public function started(string $operation, ?int $totalBytes): void
            {
                $this->events[] = ['event' => 'started', 'args' => [$operation, $totalBytes]];
            }

            public function progress(int $bytesDone): void
            {
                $this->events[] = ['event' => 'progress', 'args' => [$bytesDone]];
            }

            public function completed(int $bytesDone): void
            {
                $this->events[] = ['event' => 'completed', 'args' => [$bytesDone]];
            }

            public function failed(\Throwable $e): void
            {
                $this->events[] = ['event' => 'failed', 'args' => [$e]];
            }
        };
    }

    /**
     * @Given /^the chunk size is (\d+)$/
     */
    public function chunkSizeIs(int $bytes): void
    {
        $this->requireClient()->setChunkSize($bytes);
    }

    /**
     * @When /^I upload "([^"]+)" to "([^"]+)" with the listener$/
     */
    public function iUploadWithListener(string $localName, string $remotePath): void
    {
        try {
            /** @var ProgressListenerInterface $listener */
            $listener = $this->progressRecorder;
            $this->requireClient()->upload($this->tmpDir . '/' . $localName, $remotePath, $listener);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the listener observed the lifecycle started, progress, completed for "([^"]+)"$/
     */
    public function listenerObservedLifecycle(string $operation): void
    {
        $rec = $this->progressRecorder;
        Assert::assertNotNull($rec);
        /** @var list<array{event: string, args: array<int, mixed>}> $events */
        $events = $rec->events;
        Assert::assertNotEmpty($events);
        Assert::assertSame('started', $events[0]['event']);
        Assert::assertSame($operation, $events[0]['args'][0]);
        Assert::assertSame('completed', $events[count($events) - 1]['event']);

        $progressCount = count(array_filter($events, static fn($e): bool => $e['event'] === 'progress'));
        Assert::assertGreaterThan(0, $progressCount, 'expected at least one progress emission');
    }

    /**
     * @Then /^the listener observed a final byte count of (\d+)$/
     */
    public function listenerFinalByteCount(int $expected): void
    {
        $rec = $this->progressRecorder;
        Assert::assertNotNull($rec);
        /** @var list<array{event: string, args: array<int, mixed>}> $events */
        $events = $rec->events;
        Assert::assertSame('completed', $events[count($events) - 1]['event']);
        Assert::assertSame($expected, $events[count($events) - 1]['args'][0]);
    }

    /**
     * @Given /^I have a local directory "([^"]+)" with files:$/
     */
    public function iHaveALocalDirectoryWithFiles(string $dir, TableNode $table): void
    {
        $root = $this->tmpDir . '/' . trim($dir, '/');
        if (! is_dir($root)) {
            mkdir($root, 0o755, true);
        }
        foreach ($table->getHash() as $row) {
            $path = $root . '/' . ltrim($row['path'], '/');
            $parent = \dirname($path);
            if (! is_dir($parent)) {
                mkdir($parent, 0o755, true);
            }
            file_put_contents($path, $row['contents']);
        }
    }

    /**
     * @Given /^the local directory "([^"]+)" also has an empty subdirectory "([^"]+)"$/
     */
    public function localDirHasEmptySubdir(string $dir, string $sub): void
    {
        $path = $this->tmpDir . '/' . trim($dir, '/') . '/' . trim($sub, '/');
        if (! is_dir($path)) {
            mkdir($path, 0o755, true);
        }
    }

    /**
     * @When /^I uploadDirectory "([^"]+)" to "([^"]+)"$/
     */
    public function iUploadDirectory(string $localDir, string $remoteDir): void
    {
        try {
            $this->lastUploadResult = $this->requireClient()->uploadDirectory(
                $this->tmpDir . '/' . trim($localDir, '/'),
                $remoteDir,
            );
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I downloadDirectory "([^"]+)" to "([^"]+)"$/
     */
    public function iDownloadDirectory(string $remoteDir, string $localDir): void
    {
        try {
            $this->lastDownloadResult = $this->requireClient()->downloadDirectory(
                $remoteDir,
                $this->tmpDir . '/' . trim($localDir, '/'),
            );
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I removeDirectoryTree "([^"]+)"$/
     */
    public function iRemoveDirectoryTree(string $remoteDir): void
    {
        try {
            $this->requireClient()->removeDirectoryTree($remoteDir);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the upload result reports (\d+) files and (\d+) bytes transferred$/
     */
    public function uploadResultReports(int $files, int $bytes): void
    {
        $r = $this->lastUploadResult;
        if ($r === null) {
            throw new \RuntimeException(
                'No upload result captured. lastError = '
                . ($this->lastError === null ? '(none)' : $this->lastError::class . ': ' . $this->lastError->getMessage()),
            );
        }
        if ($r->filesTransferred !== $files || $r->bytesTransferred !== $bytes) {
            throw new \RuntimeException(\sprintf(
                'upload result mismatch: expected %d files / %d bytes, got %d / %d',
                $files,
                $bytes,
                $r->filesTransferred,
                $r->bytesTransferred,
            ));
        }
    }

    /**
     * @Then /^the local directory "([^"]+)" exists$/
     */
    public function localDirectoryExists(string $dir): void
    {
        Assert::assertDirectoryExists($this->tmpDir . '/' . trim($dir, '/'));
    }

    /**
     * @Then /^the remote directory "([^"]+)" no longer exists$/
     */
    public function remoteDirectoryGone(string $dir): void
    {
        // fileExists on a directory path returns true if it's there, false if not.
        Assert::assertFalse(
            $this->requireClient()->fileExists($dir),
            'expected remote directory to be gone: ' . $dir,
        );
    }

    /**
     * @Given /^I have an empty known_hosts file$/
     */
    public function emptyKnownHostsFile(): void
    {
        $this->knownHostsPath = $this->tmpDir . '/known_hosts';
        file_put_contents($this->knownHostsPath, '');
    }

    /**
     * @Given /^I have a known_hosts file with a tampered fingerprint for ([^\s]+)$/
     */
    public function tamperedKnownHostsFile(string $host): void
    {
        $this->knownHostsPath = $this->tmpDir . '/known_hosts';
        // Pin a deliberately-wrong SHA-1 fingerprint. The server's actual
        // SHA-1 won't match this, so verifyHost() returns Mismatch.
        // The stored hostspec must match what the client looks up:
        // [host]:port form for the runtime port (parameterised so the same
        // scenario covers both atmoz on 2222 and OpenSSH on 2223).
        file_put_contents(
            $this->knownHostsPath,
            '[' . $host . ']:' . $this->port . ' sha1-fpr ' . str_repeat('0', 40) . "\n",
        );
    }

    /**
     * @Given /^I connect once with the known_hosts file and TrustOnFirstUse$/
     */
    public function iConnectOnceWithTofu(): void
    {
        $primer = new SftpClient();
        $primer->setCredentials(Credentials::withPassword($this->user, $this->pass));
        $primer->connect(
            $this->host,
            $this->port,
            knownHostsFile: $this->knownHostsPath,
            onUnknownHost: UnknownHostPolicy::TrustOnFirstUse,
        );
        $primer->close();
    }

    /**
     * @When /^I connect with the known_hosts file and TrustOnFirstUse$/
     */
    public function iConnectWithTofu(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));

        try {
            $this->client->connect(
                $this->host,
                $this->port,
                knownHostsFile: $this->knownHostsPath,
                onUnknownHost: UnknownHostPolicy::TrustOnFirstUse,
            );
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I connect with the known_hosts file and Reject policy$/
     */
    public function iConnectWithReject(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword($this->user, $this->pass));

        try {
            $this->client->connect(
                $this->host,
                $this->port,
                knownHostsFile: $this->knownHostsPath,
                onUnknownHost: UnknownHostPolicy::Reject,
            );
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the known_hosts file now lists 127\.0\.0\.1 with a sha256-fpr entry$/
     */
    public function knownHostsFileListsTofuEntry(): void
    {
        Assert::assertNotNull($this->knownHostsPath);
        $body = file_get_contents($this->knownHostsPath);
        Assert::assertNotFalse($body);
        // Plain preg_match + assertSame keeps us off PHPUnit's
        // Configuration-dependent formatter. Port is parameterised so
        // the same scenario runs against atmoz (2222) and OpenSSH (2223).
        $pattern = '/^\[' . preg_quote($this->host, '/') . '\]:' . $this->port . ' sha1-fpr [0-9a-f]{40}$/m';
        Assert::assertSame(
            1,
            preg_match($pattern, $body),
            'expected a [' . $this->host . ']:' . $this->port . ' sha1-fpr line in known_hosts',
        );
    }

    /**
     * @Then /^the known_hosts file has exactly one entry$/
     */
    public function knownHostsFileHasExactlyOneEntry(): void
    {
        Assert::assertNotNull($this->knownHostsPath);
        $body = file_get_contents($this->knownHostsPath);
        Assert::assertNotFalse($body);
        $entryLines = array_filter(
            explode("\n", $body),
            static fn(string $l): bool => str_contains($l, 'sha1-fpr '),
        );
        Assert::assertCount(1, $entryLines, 'expected exactly one sha1-fpr entry');
    }

    /**
     * @Then /^a known-hosts rejection is reported$/
     */
    public function knownHostsRejectionReported(): void
    {
        Assert::assertInstanceOf(ConnectionException::class, $this->lastError);
        $msg = $this->lastError->getMessage();
        Assert::assertTrue(
            str_contains($msg, 'Unknown host'),
            'expected an "Unknown host" rejection; got: ' . $msg,
        );
    }

    /**
     * @Then /^a known-hosts mismatch is reported$/
     */
    public function knownHostsMismatchReported(): void
    {
        Assert::assertInstanceOf(ConnectionException::class, $this->lastError);
        $msg = $this->lastError->getMessage();
        Assert::assertTrue(
            str_contains($msg, 'Known-hosts mismatch'),
            'expected a "Known-hosts mismatch" error; got: ' . $msg,
        );
    }

    /**
     * @Then /^no remote partial file is left behind in "([^"]+)"$/
     */
    public function noRemotePartialLeft(string $dir): void
    {
        $entries = $this->requireClient()->getFileList($dir, includeDotEntries: true);
        $partials = array_filter(
            $entries,
            static fn(string $name): bool => str_contains($name, '.partial-') || str_ends_with($name, '.resume'),
        );
        Assert::assertSame(
            [],
            array_values($partials),
            'Expected no .partial-* / .resume sibling files; found: ' . implode(', ', $partials),
        );
    }

    /**
     * @When /^I remove "([^"]+)"$/
     */
    public function iRemove(string $remotePath): void
    {
        try {
            $this->requireClient()->remove($remotePath);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I rename "([^"]+)" to "([^"]+)"$/
     */
    public function iRename(string $from, string $to): void
    {
        try {
            $this->requireClient()->rename($from, $to);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I create directory "([^"]+)"$/
     */
    public function iCreateDirectory(string $path): void
    {
        try {
            $this->requireClient()->makeDirectory($path);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @When /^I remove directory "([^"]+)"$/
     */
    public function iRemoveDirectory(string $path): void
    {
        try {
            $this->requireClient()->removeDirectory($path);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the connection succeeds$/
     */
    public function connectionSucceeds(): void
    {
        Assert::assertNull(
            $this->lastError,
            'Expected successful connection, got: ' . ($this->lastError?->getMessage() ?? ''),
        );
    }

    /**
     * @Then /^authentication is rejected$/
     */
    public function authenticationIsRejected(): void
    {
        Assert::assertInstanceOf(AuthenticationException::class, $this->lastError);
    }

    /**
     * @Then /^the connection fails with a fingerprint mismatch$/
     */
    public function fingerprintMismatch(): void
    {
        Assert::assertInstanceOf(ConnectionException::class, $this->lastError);
        Assert::assertStringContainsString('fingerprint mismatch', $this->lastError->getMessage());
    }

    /**
     * @Then /^the remote file "([^"]+)" contains "([^"]*)"$/
     */
    public function remoteFileContains(string $remotePath, string $expected): void
    {
        $local = $this->tmpDir . '/__verify_' . bin2hex(random_bytes(3));
        $this->requireClient()->download($remotePath, $local);
        Assert::assertSame($expected, file_get_contents($local));
    }

    /**
     * @Then /^the local file "([^"]+)" contains "([^"]*)"$/
     */
    public function localFileContains(string $name, string $expected): void
    {
        Assert::assertSame($expected, file_get_contents($this->tmpDir . '/' . $name));
    }

    /**
     * @Then /^the remote file "([^"]+)" exists$/
     */
    public function remoteFileExists(string $remotePath): void
    {
        Assert::assertTrue($this->requireClient()->fileExists($remotePath));
    }

    /**
     * @Then /^the remote file "([^"]+)" does not exist$/
     */
    public function remoteFileDoesNotExist(string $remotePath): void
    {
        Assert::assertFalse($this->requireClient()->fileExists($remotePath));
    }

    /**
     * @Then /^a transfer error is reported$/
     */
    public function transferErrorReported(): void
    {
        Assert::assertInstanceOf(TransferException::class, $this->lastError);
    }

    /**
     * @Then /^a filesystem error is reported$/
     */
    public function filesystemErrorReported(): void
    {
        Assert::assertInstanceOf(RemoteFilesystemException::class, $this->lastError);
    }

    /**
     * @Then /^a path validation error is reported$/
     */
    public function pathValidationErrorReported(): void
    {
        Assert::assertInstanceOf(InvalidPathException::class, $this->lastError);
    }

    // ───────────────────────────────────────────────────────────────────
    // README example scenarios — see tests/functional/features/readme.feature
    // ───────────────────────────────────────────────────────────────────

    /**
     * @Given /^a StaticCredentialsLoader carrying the fixture credentials$/
     */
    public function staticCredentialsLoaderCarryingFixture(): void
    {
        $loader = new StaticCredentialsLoader(Credentials::withPassword($this->user, $this->pass));
        $this->client = new SftpClient();
        $this->client->setCredentialsLoader($loader);
    }

    /**
     * @When /^I connect through the loader with no explicit credentials$/
     */
    public function connectThroughLoaderWithoutCredentials(): void
    {
        try {
            $this->requireClient()->connect($this->host, $this->port);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    /**
     * @Then /^the client's getCredentials returns the loader-resolved value$/
     */
    public function clientCredentialsResolvedByLoader(): void
    {
        $resolved = $this->requireClient()->getCredentials();
        Assert::assertNotNull($resolved, 'loader should have resolved credentials by now');
        Assert::assertSame($this->user, $resolved->getUsername());
    }

    /**
     * @Given /^the client has file-size verification enabled$/
     */
    public function clientHasFileSizeVerification(): void
    {
        $this->requireClient()->enableFileSizeVerification();
    }

    /**
     * @Given /^the client has atomic uploads disabled$/
     */
    public function clientHasAtomicUploadsDisabled(): void
    {
        $this->requireClient()->disableAtomicUploads();
    }

    /**
     * @When /^I walk "([^"]+)"$/
     */
    public function iWalk(string $remoteDir): void
    {
        $entries = [];
        foreach ($this->requireClient()->walk($remoteDir) as $entry) {
            $entries[] = $entry;
        }
        $this->lastWalk = $entries;
    }

    /**
     * @Then /^the walk yielded (\d+) entries$/
     */
    public function walkYieldedNEntries(int $expected): void
    {
        Assert::assertNotNull($this->lastWalk, 'no walk step ran before this assertion');
        Assert::assertCount($expected, $this->lastWalk);
    }

    /**
     * @Then /^every directory in the walk appears after its children$/
     */
    public function walkPostOrderInvariant(): void
    {
        Assert::assertNotNull($this->lastWalk);
        $position = [];
        foreach ($this->lastWalk as $i => $e) {
            $position[$e->path] = $i;
        }
        foreach ($this->lastWalk as $entry) {
            if ($entry->type !== EntryType::Directory) {
                continue;
            }
            $parentPos = $position[$entry->path];
            // every entry whose path is a strict descendant of $entry->path
            // must appear EARLIER in the listing.
            foreach ($position as $candidatePath => $candidatePos) {
                if ($candidatePath === $entry->path) {
                    continue;
                }
                if (str_starts_with($candidatePath, $entry->path . '/')) {
                    Assert::assertLessThan(
                        $parentPos,
                        $candidatePos,
                        "child {$candidatePath} (pos {$candidatePos}) must precede parent {$entry->path} (pos {$parentPos})",
                    );
                }
            }
        }
    }

    /**
     * @Given /^I install a NoRetryPolicy on the client$/
     */
    public function installNoRetryPolicy(): void
    {
        $this->requireClient()->setRetryPolicy(new NoRetryPolicy());
    }

    /**
     * @Then /^ping returns true$/
     */
    public function pingReturnsTrue(): void
    {
        Assert::assertTrue($this->requireClient()->ping());
    }

    /**
     * @Then /^ping returns false$/
     */
    public function pingReturnsFalse(): void
    {
        Assert::assertFalse($this->requireClient()->ping());
    }

    /**
     * @When /^I close the client$/
     */
    public function iCloseTheClient(): void
    {
        $this->requireClient()->close();
    }

    /**
     * @Given /^the client uses a RedownloadRemoteHasher with algorithm "([^"]+)"$/
     */
    public function clientUsesRedownloadHasher(string $algorithm): void
    {
        $this->requireClient()->setRemoteHasher(new RedownloadRemoteHasher($algorithm));
    }

    /**
     * @Given /^the client has remote prefix "([^"]+)"$/
     */
    public function clientHasRemotePrefix(string $prefix): void
    {
        $this->requireClient()->setRemotePrefix($prefix);
        // Make sure the prefix path exists so upload() (which doesn't
        // mkdir intermediate dirs) doesn't fail with "no such directory".
        try {
            $this->requireClient()->makeDirectory(rtrim($prefix, '/'), recursive: true);
        } catch (\Throwable) {
            // ignore — already exists or unprivileged path
        }
    }

    /**
     * @Given /^the client has a capturing logger$/
     */
    public function clientHasCapturingLogger(): void
    {
        $this->capturingLogger = new CapturingLogger();
        $this->requireClient()->setLogger($this->capturingLogger);
    }

    /**
     * @Given /^the client log context is "([^"]+)" = "([^"]+)" and "([^"]+)" = "([^"]+)"$/
     */
    public function clientLogContextTwoKeys(string $k1, string $v1, string $k2, string $v2): void
    {
        $this->requireClient()->setLogContext([$k1 => $v1, $k2 => $v2]);
    }

    /**
     * @Then /^every captured log record carries context key "([^"]+)" with value "([^"]+)"$/
     */
    public function everyCapturedLogRecordCarriesKeyWithValue(string $key, string $value): void
    {
        Assert::assertNotNull($this->capturingLogger);
        Assert::assertNotEmpty($this->capturingLogger->records);
        foreach ($this->capturingLogger->records as $r) {
            Assert::assertArrayHasKey(
                $key,
                $r['context'],
                'log record at level ' . $r['level'] . ' missing key "' . $key . '"',
            );
            Assert::assertSame(
                $value,
                $r['context'][$key],
                'log record at level ' . $r['level'] . ' had unexpected value for "' . $key . '"',
            );
        }
    }

    /**
     * @Then /^every captured log record carries a "([^"]+)" key$/
     */
    public function everyCapturedLogRecordCarriesKey(string $key): void
    {
        Assert::assertNotNull($this->capturingLogger);
        Assert::assertNotEmpty($this->capturingLogger->records);
        foreach ($this->capturingLogger->records as $r) {
            Assert::assertArrayHasKey($key, $r['context']);
        }
    }

    /**
     * @Then /^a single SshException was thrown$/
     */
    public function singleSshExceptionThrown(): void
    {
        Assert::assertInstanceOf(
            SshException::class,
            $this->lastError,
            'expected a library exception (SshException root); got '
            . ($this->lastError === null ? 'no exception at all' : $this->lastError::class),
        );
    }

    // ───────────────────────────────────────────────────────────────────

    private function tryConnect(): void
    {
        try {
            $this->requireClient()->connect($this->host, $this->port);
        } catch (\Throwable $e) {
            $this->lastError = $e;
        }
    }

    private function requireClient(): SftpClient
    {
        if ($this->client === null) {
            throw new \LogicException('No SFTP client initialised. Wire it via an earlier step.');
        }

        return $this->client;
    }
}
