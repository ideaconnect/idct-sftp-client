<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Static-scan guard: no log call anywhere in src/ may pass a context value
 * derived from a password / passphrase. We can't reliably trace data flow
 * with a regex, so we use a conservative proxy: if a single statement
 * contains both a log invocation and the literal tokens "password" or
 * "passphrase", fail the build and force the author to refactor.
 *
 * Acceptance per PRODUCTION_GRADE.md §P7 — "a test that grep's src/ for
 * any string containing 'password' or 'passphrase' near a log call — fail
 * if found".
 *
 * Tradeoffs:
 * - False positives: if you legitimately log the string "password mode
 *   selected", this fails. Rename your message in that case.
 * - False negatives: data flow isn't traced. If you put $secret into the
 *   context map under a key not named password/passphrase, the linter
 *   misses it. This test is one belt; code review is the suspenders.
 */
final class LoggerRedactionLintTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function sourceFiles(): iterable
    {
        $base = dirname(__DIR__, 2) . '/src';
        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($base)) as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $path = $file->getPathname();
                yield substr($path, strlen($base) + 1) => [$path];
            }
        }
    }

    #[DataProvider('sourceFiles')]
    public function testNoLogCallContainsSensitiveTokens(string $path): void
    {
        $source = file_get_contents($path);
        self::assertNotFalse($source);

        // Split on ';' to inspect one statement at a time. PHP statements
        // commonly end with ';'; the only failure mode is multi-line method
        // calls, which still get joined into a single chunk via str_replace
        // newline-to-space below.
        $flat = str_replace(["\r", "\n"], ' ', $source);
        $statements = explode(';', $flat);

        $logCallPattern = '/->(log|emergency|alert|critical|error|warning|notice|info|debug)\(/';

        foreach ($statements as $i => $stmt) {
            if (preg_match($logCallPattern, $stmt) !== 1) {
                continue;
            }
            $haystack = strtolower($stmt);
            self::assertFalse(
                str_contains($haystack, 'password'),
                "Log call in {$path} (stmt #{$i}) contains the token 'password'. "
                    . "Refactor: don't pass secrets through the logger context. "
                    . "Statement: " . trim($stmt),
            );
            self::assertFalse(
                str_contains($haystack, 'passphrase'),
                "Log call in {$path} (stmt #{$i}) contains the token 'passphrase'. "
                    . "Refactor: don't pass secrets through the logger context. "
                    . "Statement: " . trim($stmt),
            );
        }
    }
}
