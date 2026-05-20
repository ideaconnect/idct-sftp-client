<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Support;

use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Minimal in-memory PSR-3 logger for tests. psr/log 3.x dropped the bundled
 * TestLogger, so we hand-roll this one rather than pull a fixture-only
 * dependency.
 *
 * Records are stored in insertion order with their level, message, and
 * context, so tests can assert on whichever shape they need (level present,
 * context key set, message substring) without fighting an opinionated API.
 */
final class CapturingLogger extends AbstractLogger implements LoggerInterface
{
    /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
    public array $records = [];

    /**
     * @param array<string, mixed> $context
     */
    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->records[] = [
            'level' => (string) $level,
            'message' => (string) $message,
            'context' => $context,
        ];
    }

    /**
     * @return list<array{level: string, message: string, context: array<string, mixed>}>
     */
    public function at(string $level): array
    {
        return array_values(array_filter(
            $this->records,
            static fn(array $r): bool => $r['level'] === $level,
        ));
    }

    public function hasMessageContaining(string $needle): bool
    {
        foreach ($this->records as $r) {
            if (str_contains($r['message'], $needle)) {
                return true;
            }
        }

        return false;
    }
}
