#!/usr/bin/env php
<?php

/**
 * P11 follow-up — long-running soak script.
 *
 * Usage:
 *   php tests/soak/soak.php [duration-seconds] [period-seconds]
 *
 * Defaults: 6h (21600s) total runtime, 30s between transfer cycles.
 * Each cycle uploads + downloads a 1 MiB random file, asserts byte-
 * identity, and unlinks the remote artefact. Records peak memory and
 * total transfer count to a JSON summary at tests/soak/build/summary.json.
 *
 * Designed to be invokable from CI's manual-trigger workflow
 * (`.github/workflows/soak.yml`) with a short duration for smoke tests
 * (e.g. `php soak.php 900`) and from a self-hosted runner for the full
 * plan-mandated 24h target.
 *
 * NOT meant to run inside the main CI lane — GitHub-hosted runners have
 * a 6h job ceiling, so the longest hosted soak we ship caps there.
 *
 * Exits 0 on clean completion, 1 on any transfer / verification failure.
 */

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\SftpClient;

$durationSec = isset($argv[1]) ? (int) $argv[1] : 21600; // 6h default
$periodSec   = isset($argv[2]) ? (int) $argv[2] : 30;    // every 30s

$host = getenv('SFTP_HOST') !== false ? (string) getenv('SFTP_HOST') : '127.0.0.1';
$port = getenv('SFTP_PORT') !== false ? (int) getenv('SFTP_PORT') : 2222;
$user = getenv('SFTP_USER') !== false ? (string) getenv('SFTP_USER') : 'tester';
$pass = getenv('SFTP_PASS') !== false ? (string) getenv('SFTP_PASS') : 'testerpass';

$summaryPath = __DIR__ . '/build/summary.json';
@mkdir(dirname($summaryPath), 0o755, true);

$client = new SftpClient();
$client->setCredentials(Credentials::withPassword($user, $pass));
$client->connect($host, $port);

$start = microtime(true);
$cycles = 0;
$bytes = 0;
$failures = 0;
$peakMemBytes = 0;

$payload = random_bytes(1 << 20); // 1 MiB
$expectedSha = hash('sha256', $payload);

$tmp = sys_get_temp_dir() . '/idct-soak-' . bin2hex(random_bytes(4));
@mkdir($tmp, 0o700, true);
$localSrc = $tmp . '/src.bin';
$localDl  = $tmp . '/dl.bin';
file_put_contents($localSrc, $payload);

echo "soak: duration={$durationSec}s period={$periodSec}s target={$host}:{$port}\n";

while ((microtime(true) - $start) < $durationSec) {
    $cycleStart = microtime(true);
    $remote = '/data/soak-' . bin2hex(random_bytes(4)) . '.bin';

    try {
        $client->upload($localSrc, $remote);
        $client->download($remote, $localDl);
        $actual = hash_file('sha256', $localDl);
        if ($actual !== $expectedSha) {
            throw new \RuntimeException("hash mismatch after cycle {$cycles}");
        }
        $client->remove($remote);
        $cycles++;
        $bytes += 2 * (1 << 20); // up + down
        $peakMemBytes = max($peakMemBytes, memory_get_peak_usage(true));
    } catch (\Throwable $e) {
        $failures++;
        echo "[FAIL cycle={$cycles}] " . $e::class . ': ' . $e->getMessage() . "\n";
    }

    $elapsedCycle = microtime(true) - $cycleStart;
    $sleep = max(0, $periodSec - $elapsedCycle);
    if ($sleep > 0) {
        // Tight enough for short soaks (30s period), nothing fancier needed.
        usleep((int) ($sleep * 1_000_000));
    }

    if ($cycles % 60 === 0 && $cycles > 0) {
        $heartbeat = sprintf(
            "soak: %d cycles, %.2f GiB total, peak mem %.1f MiB, failures=%d\n",
            $cycles,
            $bytes / (1 << 30),
            $peakMemBytes / (1 << 20),
            $failures,
        );
        echo $heartbeat;
    }
}

$client->close();

$elapsed = microtime(true) - $start;
$summary = [
    'host' => $host,
    'port' => $port,
    'duration_target_s' => $durationSec,
    'duration_actual_s' => (int) $elapsed,
    'period_s' => $periodSec,
    'cycles' => $cycles,
    'bytes_transferred' => $bytes,
    'failures' => $failures,
    'peak_memory_bytes' => $peakMemBytes,
    'completed_at' => date(\DATE_ATOM),
];
file_put_contents(
    $summaryPath,
    json_encode($summary, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
);

echo "soak: done. {$cycles} cycles, {$failures} failures. summary=" . $summaryPath . "\n";

@unlink($localSrc);
@unlink($localDl);
@rmdir($tmp);

exit($failures === 0 ? 0 : 1);
