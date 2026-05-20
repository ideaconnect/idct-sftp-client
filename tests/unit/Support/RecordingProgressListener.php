<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\Support;

use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;

/**
 * Records every lifecycle callback so tests can assert on the exact event
 * sequence (started → progress×N → completed | failed).
 *
 * @phpstan-type Event array{event: string, args: array<int, mixed>}
 */
final class RecordingProgressListener implements ProgressListenerInterface
{
    /** @var list<Event> */
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

    /**
     * @return list<string>
     */
    public function eventNames(): array
    {
        return array_map(static fn(array $r): string => $r['event'], $this->events);
    }

    /**
     * @return list<int>
     */
    public function progressBytes(): array
    {
        $out = [];
        foreach ($this->events as $e) {
            if ($e['event'] === 'progress') {
                $out[] = (int) $e['args'][0];
            }
        }

        return $out;
    }
}
