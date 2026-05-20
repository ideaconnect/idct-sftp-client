<?php
/**
 * 02 — CLI progress bar via ProgressListenerInterface
 *
 * Sends a 256 KiB file through a 16 KiB chunk window so the bar
 * updates 16 times. The listener follows the lifecycle contract:
 * started → progress × N → exactly one of completed | failed.
 *
 * For a real Symfony ProgressBar, swap the body of the listener for
 * Symfony\Component\Console\Helper\ProgressBar calls — the signature
 * is identical.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use IDCT\Networking\Ssh\Progress\ProgressListenerInterface;

$progress = new class implements ProgressListenerInterface {
    private int $total = 0;

    public function started(string $operation, ?int $totalBytes): void
    {
        $this->total = $totalBytes ?? 0;
        echo "[{$operation}] starting ({$this->total} bytes)\n";
    }

    public function progress(int $bytesDone): void
    {
        $pct = $this->total > 0 ? (int) round($bytesDone / $this->total * 100) : 0;
        $width = 40;
        $filled = (int) round($pct / 100 * $width);
        echo "\r  [" . str_repeat('#', $filled) . str_repeat('.', $width - $filled) . "] {$pct}%";
    }

    public function completed(int $bytesDone): void
    {
        echo "\r  [" . str_repeat('#', 40) . "] 100%  done. ({$bytesDone} bytes)\n";
    }

    public function failed(\Throwable $e): void
    {
        echo "\n  FAILED: " . $e->getMessage() . "\n";
    }
};

$client = idct_example_client();
$client->setChunkSize(16 * 1024); // 16 KiB chunks → 16 progress events for a 256 KiB file

$tmp = sys_get_temp_dir() . '/idct-example-02-' . bin2hex(random_bytes(4));
mkdir($tmp);
$local = $tmp . '/payload.bin';
file_put_contents($local, random_bytes(256 * 1024)); // 256 KiB random

idct_example_section('upload with progress');
$client->upload($local, '/data/example-02-payload.bin', progress: $progress);

idct_example_section('download with progress');
$dl = $tmp . '/payload-dl.bin';
$client->download('/data/example-02-payload.bin', $dl, progress: $progress);

idct_example_section('cleanup');
$client->remove('/data/example-02-payload.bin');
unlink($local);
unlink($dl);
rmdir($tmp);
$client->close();

echo "\ndone.\n";
