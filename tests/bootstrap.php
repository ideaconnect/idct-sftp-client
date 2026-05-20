<?php

declare(strict_types=1);

/**
 * PHPUnit bootstrap.
 *
 * Beyond loading the autoloader, this file relocates the test process'
 * current working directory into `scratch/` under the repo root. Some
 * tests pass relative local paths to `SftpClient::download()` /
 * `resumeDownload()` to exercise documented "no prefix configured"
 * behaviour, and some surface-level mutations from Infection can
 * cause production code to fall through to a local `fopen()` even
 * when a test expects the operation to short-circuit. Without this
 * chdir, those writes land at the repo root and pollute the
 * working tree (b.txt, no-perms, etc.).
 *
 * `scratch/` is `.gitignore`d so anything that does end up here stays
 * out of `git status`; the directory is also a convenient place for
 * humans to drop ad-hoc test artifacts (see CONTRIBUTING.md).
 */
require __DIR__ . '/../vendor/autoload.php';

$scratch = \dirname(__DIR__) . '/scratch';
if (! is_dir($scratch) && ! @mkdir($scratch, 0o755, true) && ! is_dir($scratch)) {
    throw new \RuntimeException("Could not create scratch directory at {$scratch}");
}
if (! @chdir($scratch)) {
    throw new \RuntimeException("Could not chdir to scratch directory at {$scratch}");
}
