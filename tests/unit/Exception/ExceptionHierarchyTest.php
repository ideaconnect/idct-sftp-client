<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Exception;

use IDCT\Networking\Ssh\Exception\AuthenticationException;
use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\ConnectionException;
use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Exception\TransferException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SshException::class)]
#[CoversClass(AuthenticationException::class)]
#[CoversClass(ConfigurationException::class)]
#[CoversClass(ConnectionException::class)]
#[CoversClass(RemoteFilesystemException::class)]
#[CoversClass(TransferException::class)]
#[UsesClass(SshException::class)]
final class ExceptionHierarchyTest extends TestCase
{
    /**
     * @return iterable<string, array{class-string<SshException>}>
     */
    public static function exceptionClasses(): iterable
    {
        yield 'authentication'      => [AuthenticationException::class];
        yield 'configuration'       => [ConfigurationException::class];
        yield 'connection'          => [ConnectionException::class];
        yield 'remote-filesystem'   => [RemoteFilesystemException::class];
        yield 'transfer'            => [TransferException::class];
    }

    /**
     * @param class-string<SshException> $class
     */
    #[DataProvider('exceptionClasses')]
    public function testExtendsSshException(string $class): void
    {
        $instance = new $class('hello');
        self::assertInstanceOf(SshException::class, $instance);
        self::assertInstanceOf(\RuntimeException::class, $instance);
        self::assertSame('hello', $instance->getMessage());
    }
}
