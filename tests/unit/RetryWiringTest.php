<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Auth\AuthMode;
use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Retry\ExponentialBackoffRetryPolicy;
use IDCT\Networking\Ssh\Retry\NoRetryPolicy;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;
use IDCT\Networking\Ssh\Tests\Support\SftpFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * P5 wiring: the retry() helper inside SftpClient honours the configured
 * policy, applies the hard never-retry rules, performs lazy reconnect on
 * dead sessions, and stops when the policy returns 0.
 *
 * Tests use small-base policies (baseMs=1, maxMs=10) so total sleep across
 * a multi-retry test stays in tens of milliseconds.
 */
#[CoversClass(SftpClient::class)]
#[UsesClass(AuthMode::class)]
#[UsesClass(Credentials::class)]
#[UsesClass(ExponentialBackoffRetryPolicy::class)]
#[UsesClass(NoRetryPolicy::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\AuthenticationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConnectionException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\TransferException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\InvalidPathException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Path\PathValidator::class)]
final class RetryWiringTest extends TestCase
{
    private SftpFixture $fixture;
    private object $session;
    private object $sftpHandle;

    /** @var Ssh2FunctionsInterface&MockObject */
    private Ssh2FunctionsInterface $ssh2;

    protected function setUp(): void
    {
        $this->fixture = new SftpFixture();
        $this->session = new \stdClass();
        $this->sftpHandle = new class {
            public function __toString(): string
            {
                return '1';
            }
        };
        $this->ssh2 = $this->createMock(Ssh2FunctionsInterface::class);
    }

    // ─── default policy + getter ───────────────────────────────────────

    public function testDefaultPolicyIsExponentialBackoff(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertInstanceOf(ExponentialBackoffRetryPolicy::class, $client->getRetryPolicy());
    }

    public function testSetRetryPolicyReplaces(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        $noRetry = new NoRetryPolicy();
        self::assertSame($client, $client->setRetryPolicy($noRetry));
        self::assertSame($noRetry, $client->getRetryPolicy());
    }

    // ─── connect: retry on transient transport failure ─────────────────

    public function testConnectRetriesOnConnectionExceptionUntilSuccess(): void
    {
        $client = new SftpClient(false, $this->ssh2, new ExponentialBackoffRetryPolicy(
            maxRetries: 3,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        // 1st + 2nd attempt: transport fail. 3rd: succeed.
        $this->ssh2->expects(self::exactly(3))
            ->method('connect')
            ->willReturnOnConsecutiveCalls(false, false, $this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);

        $client->connect('example.com');
    }

    public function testConnectGivesUpAfterMaxRetries(): void
    {
        $client = new SftpClient(false, $this->ssh2, new ExponentialBackoffRetryPolicy(
            maxRetries: 2,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        // 1 initial + 2 retries = 3 attempts; all fail.
        $this->ssh2->expects(self::exactly(3))
            ->method('connect')
            ->willReturn(false);

        $this->expectException(ConnectionException::class);
        $client->connect('example.com');
    }

    public function testConnectDoesNotRetryOnAuthenticationException(): void
    {
        $client = new SftpClient(false, $this->ssh2, new ExponentialBackoffRetryPolicy(
            maxRetries: 5,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        $this->ssh2->expects(self::once())->method('connect')->willReturn($this->session);
        $this->ssh2->expects(self::once())->method('authPassword')->willReturn(false);

        $this->expectException(AuthenticationException::class);
        $client->connect('example.com');
    }

    public function testConnectDoesNotRetryWhenCredentialsMissing(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        // No credentials → ConfigurationException, must not retry.
        $this->ssh2->expects(self::never())->method('connect');
        $this->expectException(ConfigurationException::class);
        $client->connect('example.com');
    }

    // ─── upload / download: retry on retryable TransferException ────────

    public function testUploadRetriesOnTransientTransferAndSucceeds(): void
    {
        $local = $this->fixture->rootDir . '/up.txt';
        file_put_contents($local, 'hi');

        $client = $this->connectedClient(new ExponentialBackoffRetryPolicy(
            maxRetries: 3,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));

        // First call: fail with retryable transfer error. Second: succeed by
        // returning a URI our FakeSftpStreamWrapper can write to.
        $callCount = 0;
        $this->ssh2->method('sftpStreamUri')->willReturnCallback(function () use (&$callCount): string {
            $callCount++;

            return $callCount === 1
                ? 'ssh2.sftp://1/blocked-on-first-call'
                : 'ssh2.sftp://1/dest.txt';
        });
        // Force the first remote-open to fail; second succeeds via the wrapper.
        \IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper::$openFailures['ssh2.sftp://1/blocked-on-first-call'] = true;

        // ping() during retry must succeed so we DON'T trigger a reconnect.
        $this->ssh2->method('sftpStat')->willReturn(['size' => 2]);

        $client->upload($local, '/dest.txt');

        // Verify the second attempt wrote to the wrapper's backing dir.
        self::assertSame('hi', $this->fixture->readRemote('/dest.txt'));
    }

    public function testUploadDoesNotRetryOnNonTransientTransferException(): void
    {
        // "Local file does not exist" is NOT in the retryable allowlist.
        $client = $this->connectedClient(new ExponentialBackoffRetryPolicy(
            maxRetries: 5,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));
        // No mock setup for sftpStreamUri etc., so any second attempt would
        // surface as an unmocked call. Expect exactly one attempt.
        $this->expectException(TransferException::class);
        $this->expectExceptionMessage('Local file does not exist');
        $client->upload('/no/such/file');
    }

    public function testUploadDoesNotRetryOnInvalidPathException(): void
    {
        $local = $this->fixture->rootDir . '/x';
        file_put_contents($local, 'data');
        $client = $this->connectedClient();
        $this->expectException(InvalidPathException::class);
        $client->upload($local, '../etc/passwd');
    }

    // ─── ping ───────────────────────────────────────────────────────────

    public function testPingReturnsFalseBeforeConnect(): void
    {
        $client = new SftpClient(false, $this->ssh2);
        self::assertFalse($client->ping());
    }

    public function testPingReturnsTrueWhenStatSucceeds(): void
    {
        $client = $this->connectedClient(new NoRetryPolicy());
        $this->ssh2->expects(self::once())
            ->method('sftpStat')
            ->with($this->sftpHandle, '/')
            ->willReturn(['size' => 0]);

        self::assertTrue($client->ping());
    }

    public function testPingReturnsFalseWhenStatFails(): void
    {
        $client = $this->connectedClient(new NoRetryPolicy());
        $this->ssh2->expects(self::once())
            ->method('sftpStat')
            ->with($this->sftpHandle, '/')
            ->willReturn(false);

        self::assertFalse($client->ping());
    }

    // ─── lazy reconnect ────────────────────────────────────────────────

    public function testLazyReconnectFiresWhenSessionDiesBetweenRetries(): void
    {
        $client = new SftpClient(false, $this->ssh2, new ExponentialBackoffRetryPolicy(
            maxRetries: 2,
            baseMs: 1,
            maxMs: 2,
            jitter: 0.0,
        ));
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));

        // ssh2->connect must be invoked TWICE: initial connect() + lazy reconnect
        // triggered by retry helper after ping() reports a dead session.
        $this->ssh2->expects(self::exactly(2))
            ->method('connect')
            ->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);

        // sftpStat is called twice:
        //   1) the ping() right after the first upload failure → return false (dead session)
        //   2) the ping() after the second upload failure → return ok (session is alive)
        // The first false-return is what triggers the lazy reconnect.
        $statCalls = 0;
        $this->ssh2->method('sftpStat')->willReturnCallback(function () use (&$statCalls) {
            $statCalls++;

            return $statCalls === 1 ? false : ['size' => 0];
        });

        // Make every upload attempt fail with a retryable TransferException
        // (a fopen() failure on the remote side — "Unable to open remote ...").
        $this->ssh2->method('sftpStreamUri')->willReturn('ssh2.sftp://1/blocked');
        \IDCT\Networking\Ssh\Tests\Support\FakeSftpStreamWrapper::$openFailures['ssh2.sftp://1/blocked'] = true;

        // Establish the session so retry's "sshSession !== null" branch is reachable.
        $client->connect('example.com');

        $local = $this->fixture->rootDir . '/x.txt';
        file_put_contents($local, 'x');

        try {
            $client->upload($local, '/x.txt');
            self::fail('expected eventual TransferException');
        } catch (TransferException) {
            // 1 + maxRetries (2) attempts all fail; final failure propagates.
        }

        // expects(self::exactly(2))->method('connect') above is the actual assertion:
        // it would fail if lazy reconnect didn't fire (only 1 connect call) OR if
        // it fired more than once (>2 connect calls).
    }

    // ─── defensive guards (reachable only via reflection) ─────────────

    public function testIsRetryableReturnsFalseForConfigurationException(): void
    {
        // ConfigurationException can't reach the retry helper through normal
        // flow (connect()'s "credentials must be set" check throws BEFORE the
        // retry wrapper). We invoke the private classifier directly to cover
        // the defensive `return false` branch for ConfigurationException.
        $r = new \ReflectionMethod(SftpClient::class, 'isRetryable');
        self::assertFalse($r->invoke(null, new ConfigurationException('test')));
    }

    public function testDoConnectThrowsConfigurationExceptionWhenScopeNotPrepared(): void
    {
        // doConnect() reads host/port/credentials off the instance; the public
        // connect() always sets them first. We force the invariant-violation
        // throw via reflection to cover the defensive guard at the top of
        // doConnect.
        $client = new SftpClient(false, $this->ssh2, new NoRetryPolicy());
        $r = new \ReflectionMethod(SftpClient::class, 'doConnect');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('internal invariant violation');
        $r->invoke($client);
    }

    // ─── helpers ────────────────────────────────────────────────────────

    private function connectedClient(?\IDCT\Networking\Ssh\Retry\RetryPolicyInterface $policy = null): SftpClient
    {
        // atomicUploads=false: these tests assert on upload-flow plumbing
        // (retries, message classification) and pre-date P4's atomic rename.
        // Atomic semantics get their own coverage in AtomicUploadAndResumeTest.
        $client = new SftpClient(false, $this->ssh2, $policy ?? new NoRetryPolicy(), false);
        $client->setCredentials(Credentials::withPassword('alice', 'secret'));
        $this->ssh2->method('connect')->willReturn($this->session);
        $this->ssh2->method('authPassword')->willReturn(true);
        $this->ssh2->method('sftp')->willReturn($this->sftpHandle);
        $client->connect('example.com');

        return $client;
    }
}
