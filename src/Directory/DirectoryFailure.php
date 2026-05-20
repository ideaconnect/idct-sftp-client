<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Directory;

/**
 * One per-entry failure recorded during a best-effort directory
 * operation. Populated only when the caller opted into best-effort
 * mode; abort-on-first-failure mode (the default) raises instead and
 * never produces a failure list.
 */
final readonly class DirectoryFailure
{
    /**
     * @param string $path The local or remote path the failure occurred on.
     * @param string $reason Human-readable summary — usually the exception message.
     * @param class-string<\Throwable> $exceptionClass FQN of the underlying exception.
     */
    public function __construct(
        public string $path,
        public string $reason,
        public string $exceptionClass,
    ) {}
}
