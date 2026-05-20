<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Path;

use Eris\Generator;
use Eris\TestTrait;
use IDCT\Networking\Ssh\Exception\InvalidPathException;
use IDCT\Networking\Ssh\Path\PathValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Property-based tests for {@see PathValidator}. The hand-rolled
 * data-provider matrix in {@see PathValidatorTest} covers the T1-T6
 * threat enumeration; this complements it by feeding random strings
 * and asserting the contract holds — "either accepts safely or
 * rejects with `InvalidPathException`, never crashes".
 *
 * Each property runs Eris's default 100 iterations; shrinking on
 * failure produces a minimal counterexample.
 */
#[CoversClass(PathValidator::class)]
#[UsesClass(InvalidPathException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class PathValidatorPropertyTest extends TestCase
{
    use TestTrait;

    public function testAnyInputEitherValidatesOrThrowsInvalidPath(): void
    {
        // The strongest invariant: no random byte string ever escapes
        // validateRemotePath() as an uncaught exception. It either
        // returns the path unchanged or throws InvalidPathException.
        $this->forAll(
            Generator\string(),
        )->then(function (string $candidate): void {
            try {
                $result = PathValidator::validateRemotePath($candidate);
                self::assertSame($candidate, $result, 'accepted input must be returned unchanged');
            } catch (InvalidPathException) {
                // Acceptable outcome — the contract permits rejection.
            }
        });
    }

    public function testNullByteIsAlwaysRejected(): void
    {
        $this->forAll(
            Generator\tuple(Generator\string(), Generator\string()),
        )->then(function (array $parts): void {
            $candidate = $parts[0] . "\0" . $parts[1];

            try {
                PathValidator::validateRemotePath($candidate);
                self::fail('null-byte input must be rejected: ' . bin2hex($candidate));
            } catch (InvalidPathException) {
                self::assertTrue(true); // rejection IS the assertion
            }
        });
    }

    public function testCrLfIsAlwaysRejected(): void
    {
        $controls = ["\r", "\n", "\r\n"];
        $this->forAll(
            Generator\tuple(
                Generator\string(),
                Generator\elements($controls),
                Generator\string(),
            ),
        )->then(function (array $parts): void {
            $candidate = $parts[0] . $parts[1] . $parts[2];

            try {
                PathValidator::validateRemotePath($candidate);
                self::fail('CR/LF input must be rejected: ' . bin2hex($candidate));
            } catch (InvalidPathException) {
                self::assertTrue(true); // rejection IS the assertion
            }
        });
    }

    public function testTraversalComponentIsAlwaysRejected(): void
    {
        // Construct "<safe>/../<safe>" — the `..` component must trip
        // the traversal check regardless of what surrounds it.
        $this->forAll(
            Generator\tuple(
                Generator\elements(['', 'a', 'dir', 'deep/path']),
                Generator\elements(['', 'b', 'tail', 'and/more']),
            ),
        )->then(function (array $parts): void {
            $prefix = $parts[0] === '' ? '' : $parts[0] . '/';
            $suffix = $parts[1] === '' ? '' : '/' . $parts[1];
            $candidate = $prefix . '..' . $suffix;

            try {
                PathValidator::validateRemotePath($candidate);
                self::fail('traversal must be rejected: ' . $candidate);
            } catch (InvalidPathException) {
                self::assertTrue(true); // rejection IS the assertion
            }
        });
    }

    public function testOverLengthPathIsAlwaysRejected(): void
    {
        // The cap is per-call; default DEFAULT_MAX_LENGTH = 4096. Any
        // path strictly longer must be rejected. We bound the
        // generator's chars to plain ASCII to avoid accidentally
        // tripping the control-char rule first (which would be a valid
        // rejection — but for a DIFFERENT reason than we're testing).
        $this->forAll(
            Generator\choose(
                PathValidator::DEFAULT_MAX_LENGTH + 1,
                PathValidator::DEFAULT_MAX_LENGTH + 50,
            ),
        )->then(function (int $length): void {
            $candidate = '/' . str_repeat('a', $length - 1);

            try {
                PathValidator::validateRemotePath($candidate);
                self::fail('over-length path must be rejected: length=' . $length);
            } catch (InvalidPathException $e) {
                self::assertStringContainsString('exceeds', $e->getMessage());
            }
        });
    }

    public function testBenignAsciiPathsAreAlwaysAccepted(): void
    {
        // Positive property: an ASCII path with only [a-z0-9_-./] and
        // no `.`/`..` components and length < cap should always be
        // accepted unchanged. Validates we're not over-rejecting.
        $this->forAll(
            Generator\seq(
                Generator\elements(
                    'a',
                    'b',
                    'c',
                    'd',
                    'e',
                    'f',
                    '0',
                    '1',
                    '2',
                    '_',
                    '-',
                    'x',
                    'y',
                    'z',
                ),
            ),
        )->then(function (array $chars): void {
            if ($chars === []) {
                return; // empty string is a documented rejection
            }
            $candidate = '/uploads/' . implode('', $chars);
            self::assertSame($candidate, PathValidator::validateRemotePath($candidate));
        });
    }
}
