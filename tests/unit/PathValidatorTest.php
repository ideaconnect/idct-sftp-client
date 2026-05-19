<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Path\PathValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PathValidator::class)]
#[UsesClass(InvalidPathException::class)]
#[UsesClass(ConfigurationException::class)]
#[UsesClass(SshException::class)]
final class PathValidatorTest extends TestCase
{
    // ─── happy path ─────────────────────────────────────────────────────

    /**
     * @return iterable<string, array{string}>
     */
    public static function validPaths(): iterable
    {
        yield 'simple absolute'           => ['/uploads/file.bin'];
        yield 'simple relative'           => ['report.csv'];
        yield 'nested absolute'           => ['/a/b/c/d.txt'];
        yield 'nested relative'           => ['dir/sub/file.txt'];
        yield 'root only'                 => ['/'];
        yield 'filename with spaces'      => ['/uploads/my file.txt'];
        yield 'utf-8 filename'            => ['/uploads/ünîçødé.txt'];
        yield 'trailing slash'            => ['/uploads/'];
        yield 'underscores and hyphens'   => ['/var-data/sub_dir/file-name_1.txt'];
        yield 'dot inside filename'       => ['/uploads/file.with.dots.txt'];
        yield 'leading dot filename'      => ['/uploads/.hidden'];
        yield 'numeric filename'          => ['/uploads/12345'];
    }

    #[DataProvider('validPaths')]
    public function testValidPathsAreAccepted(string $path): void
    {
        self::assertSame($path, PathValidator::validateRemotePath($path));
    }

    // ─── T1/T5: path traversal ──────────────────────────────────────────

    /**
     * @return iterable<string, array{string}>
     */
    public static function traversalPaths(): iterable
    {
        yield 'literal ..'                   => ['..'];
        yield 'literal .'                    => ['.'];
        yield 'leading ../'                  => ['../etc/passwd'];
        yield 'middle /../'                  => ['/uploads/../etc/passwd'];
        yield 'trailing /..'                 => ['/uploads/..'];
        yield 'lone . component'             => ['/uploads/./file.txt'];
        yield 'relative ..'                  => ['foo/../bar'];
        yield 'all-dots multi'               => ['./../etc'];
    }

    #[DataProvider('traversalPaths')]
    public function testTraversalPathsAreRejected(string $path): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('not permitted (traversal)');
        PathValidator::validateRemotePath($path);
    }

    // ─── T2/T3: control characters ──────────────────────────────────────

    public function testNullByteRejected(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('null byte');
        PathValidator::validateRemotePath("/uploads/good\0bad");
    }

    public function testCarriageReturnRejected(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('CR or LF');
        PathValidator::validateRemotePath("/uploads/good\rbad");
    }

    public function testLineFeedRejected(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('CR or LF');
        PathValidator::validateRemotePath("/uploads/good\nbad");
    }

    public function testPathWithBothCrAndLfRejected(): void
    {
        // Exercises the short-circuit path where the LHS (`str_contains
        // $path, "\r"`) returns true and the RHS never evaluates. Without
        // this case the `||` branch coverage for line 74 has one arm
        // (LHS-true-RHS-skipped) that's never hit, since the existing
        // testCarriageReturnRejected sends a path with `\r` but no `\n`
        // — both halves of the OR get evaluated for that specific input.
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('CR or LF');
        PathValidator::validateRemotePath("/uploads/g\r\nood");
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherControlChars(): iterable
    {
        yield 'tab'         => ["/uploads/good\tbad"];
        yield 'bell'        => ["/uploads/good\x07bad"];
        yield 'escape'      => ["/uploads/good\x1Bbad"];
        yield 'DEL'         => ["/uploads/good\x7Fbad"];
    }

    #[DataProvider('otherControlChars')]
    public function testOtherControlCharsRejected(string $path): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('control character');
        PathValidator::validateRemotePath($path);
    }

    // ─── T4: length / empty ─────────────────────────────────────────────

    public function testEmptyPathRejected(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('must not be empty');
        PathValidator::validateRemotePath('');
    }

    public function testDefaultLengthBoundaryAccepted(): void
    {
        $path = '/' . str_repeat('a', PathValidator::DEFAULT_MAX_LENGTH - 1);
        self::assertSame($path, PathValidator::validateRemotePath($path));
    }

    public function testOverLengthRejected(): void
    {
        $path = '/' . str_repeat('a', PathValidator::DEFAULT_MAX_LENGTH);
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('exceeds 4096 bytes');
        PathValidator::validateRemotePath($path);
    }

    public function testCustomMaxLengthHonored(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('exceeds 10 bytes');
        PathValidator::validateRemotePath('/a-path-longer-than-ten', maxLength: 10);
    }

    // ─── T6: absolute-vs-relative + allowAbsolute flag ─────────────────

    public function testAbsoluteAllowedByDefault(): void
    {
        self::assertSame('/etc/passwd', PathValidator::validateRemotePath('/etc/passwd'));
    }

    public function testAbsoluteRejectedWhenDisallowed(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('Absolute remote path not permitted');
        PathValidator::validateRemotePath('/etc/passwd', allowAbsolute: false);
    }

    public function testRelativeAcceptedWhenDisallowed(): void
    {
        self::assertSame('report.csv', PathValidator::validateRemotePath('report.csv', allowAbsolute: false));
    }

    // ─── joinRemote semantics ──────────────────────────────────────────

    public function testJoinRemoteConcatenatesRelativePath(): void
    {
        self::assertSame('/uploads/report.csv', PathValidator::joinRemote('/uploads/', 'report.csv'));
    }

    public function testJoinRemoteWithEmptyPrefixPassesRelative(): void
    {
        self::assertSame('report.csv', PathValidator::joinRemote('', 'report.csv'));
    }

    public function testJoinRemoteAbsolutePathBypassesPrefix(): void
    {
        self::assertSame('/abs/path', PathValidator::joinRemote('/uploads/', '/abs/path'));
    }

    public function testJoinRemoteRejectsTraversalThroughPrefix(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('not permitted (traversal)');
        PathValidator::joinRemote('/uploads/', '../etc/passwd');
    }

    public function testJoinRemoteRejectsTraversalInJoinedResult(): void
    {
        // Caller's path component "files/x" is benign on its own, but the
        // (malicious) prefix is the attack — join still rejects via the
        // second-pass validation on the composed string.
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('not permitted (traversal)');
        PathValidator::joinRemote('/safe/../', 'files/x');
    }

    public function testJoinRemoteRejectsEmptyPathInput(): void
    {
        $this->expectException(InvalidPathException::class);
        $this->expectExceptionMessage('must not be empty');
        PathValidator::joinRemote('/uploads/', '');
    }

    // ─── exception contract ────────────────────────────────────────────

    public function testInvalidPathExceptionExtendsConfigurationAndShsException(): void
    {
        try {
            PathValidator::validateRemotePath('');
            self::fail('expected exception');
        } catch (InvalidPathException $e) {
            // Single-parent rule: every library exception extends SshException;
            // InvalidPathException specifically also extends ConfigurationException
            // so callers can narrow on "bad caller input" without enumerating types.
            self::assertInstanceOf(ConfigurationException::class, $e);
            self::assertInstanceOf(SshException::class, $e);
        }
    }
}
