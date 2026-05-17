<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Functional;

use Behat\Behat\Context\Context;
use Behat\Hook\AfterSuite;
use Behat\Hook\BeforeScenario;
use Behat\Hook\BeforeSuite;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\HostKey\FingerprintAlgorithm;
use IDCT\Networking\Ssh\HostKey\FingerprintEncoding;
use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;
use IDCT\Networking\Ssh\SftpClient;
use PHPUnit\Framework\Assert;

/**
 * Behat context that drives a real ext-ssh2 client against the atmoz/sftp
 * container started by tests/functional/bin/up.
 */
final class SftpContext implements Context
{
    private const HOST = '127.0.0.1';
    private const PORT = 2222;
    private const USER = 'tester';
    private const PASS = 'testerpass';
    private const REMOTE_BASE = '/data';

    private ?SftpClient $client = null;
    private string $tmpDir;
    private ?\Throwable $lastError = null;

    /** @var resource|null memory stream used by uploadStream/downloadStream scenarios */
    private mixed $memoryStream = null;

    /** @var resource|null sink stream used by downloadStream scenarios */
    private mixed $sinkStream = null;

    private ?int $lastDownloadBytes = null;
    private ?object $progressRecorder = null;

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
        $this->client = null;
        $this->lastError = null;
        $this->memoryStream = null;
        $this->sinkStream = null;
        $this->lastDownloadBytes = null;
        $this->progressRecorder = null;
    }

    /**
     * @Given /^I have a connected SFTP client$/
     */
    public function iHaveAConnectedSftpClient(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword(self::USER, self::PASS));
        $this->client->connect(self::HOST, self::PORT);
    }

    /**
     * @Given /^the remote directory "([^"]+)" is empty$/
     */
    public function theRemoteDirectoryIsEmpty(string $path): void
    {
        $client = $this->requireClient();

        try {
            foreach ($client->getFileList($path) as $entry) {
                try {
                    $client->remove(self::REMOTE_BASE . '/' . ltrim($entry, '/'));
                } catch (RemoteFilesystemException) {
                    // best effort cleanup
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
        $this->client->setCredentials(Credentials::withPassword(self::USER, self::PASS));
        $this->tryConnect();
    }

    /**
     * @When /^I connect with a wrong password$/
     */
    public function iConnectWithWrongPassword(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPassword(self::USER, 'wrong'));
        $this->tryConnect();
    }

    /**
     * @When /^I connect with public-key authentication$/
     */
    public function iConnectWithPubkey(): void
    {
        $this->client = new SftpClient();
        $this->client->setCredentials(Credentials::withPublicKey(
            self::USER,
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
        $this->client->setCredentials(Credentials::withPassword(self::USER, self::PASS));

        try {
            $this->client->connect(
                self::HOST,
                self::PORT,
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

    private function tryConnect(): void
    {
        try {
            $this->requireClient()->connect(self::HOST, self::PORT);
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
