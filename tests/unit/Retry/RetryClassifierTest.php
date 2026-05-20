<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Retry;

use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use IDCT\Networking\Ssh\Retry\RetryClassifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Locks down the retry classification matrix at the unit level. The
 * RetryWiringTest covers integration through SftpClient, but those
 * tests can only exercise classifications that the client itself
 * reaches via the retry() wrapper. Configuration / path-validation
 * exceptions fire BEFORE the retry loop, so they were never asked
 * about transitively — this test reaches each branch directly.
 */
#[CoversClass(RetryClassifier::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class RetryClassifierTest extends TestCase
{
    /** @return iterable<string, array{SshException, bool}> */
    public static function classifications(): iterable
    {
        yield 'InvalidPathException is never retryable (caller bug)' => [
            new InvalidPathException('bad'),
            false,
        ];
        yield 'ConfigurationException is never retryable (caller bug)' => [
            new ConfigurationException('bad'),
            false,
        ];
        yield 'AuthenticationException is never retryable (lockout risk)' => [
            new AuthenticationException('rejected'),
            false,
        ];
        yield 'ConnectionException is always retryable (transport)' => [
            new ConnectionException('peer reset'),
            true,
        ];
        yield 'TransferException with "Failed to copy" message is retryable' => [
            new TransferException('Failed to copy local stream to remote file: /a'),
            true,
        ];
        yield 'TransferException with "Unable to open remote" is retryable' => [
            new TransferException('Unable to open remote: /b'),
            true,
        ];
        yield 'TransferException with "Could not SCP-download" is retryable' => [
            new TransferException('Could not SCP-download file: /c'),
            true,
        ];
        yield 'TransferException with "Could not SCP-upload" is retryable' => [
            new TransferException('Could not SCP-upload file: /d'),
            true,
        ];
        yield 'TransferException with foreign message is NOT retryable' => [
            new TransferException('Remote file does not exist'),
            false,
        ];
        yield 'RemoteFilesystemException is NOT retryable' => [
            new RemoteFilesystemException('rmdir refused'),
            false,
        ];
    }

    #[DataProvider('classifications')]
    public function testClassifiesAccordingToHardRules(SshException $e, bool $expected): void
    {
        self::assertSame($expected, RetryClassifier::isRetryable($e));
    }

    public function testTransferMessageFragmentsListIsExposedForDocumentation(): void
    {
        // The constant is `public` so dashboards / monitoring rules can
        // mirror the classification. Lock the list shape so an
        // accidental rename here doesn't silently break callers using
        // it for telemetry.
        self::assertSame(
            ['Failed to copy', 'Unable to open remote', 'Could not SCP-download', 'Could not SCP-upload'],
            RetryClassifier::RETRYABLE_TRANSFER_MESSAGE_FRAGMENTS,
        );
    }
}
