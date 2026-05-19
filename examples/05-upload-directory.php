<?php
/**
 * 05 — recursive directory upload
 *
 * Builds a small nested local tree, uploads it under /data/example-tree/,
 * then re-runs with ConflictPolicy::Skip to demonstrate idempotence
 * (second run reports 0 new transfers).
 *
 * Run example 06 next to walk + clean up the tree this script leaves
 * behind.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use IDCT\Networking\Ssh\Directory\ConflictPolicy;

$client = idct_example_client();

$tmp = sys_get_temp_dir() . '/idct-example-05-' . bin2hex(random_bytes(4));
mkdir($tmp . '/sub/deep', 0o755, true);
mkdir($tmp . '/sub/empty', 0o755);
file_put_contents($tmp . '/a.txt', 'aaa');
file_put_contents($tmp . '/sub/b.txt', 'bb');
file_put_contents($tmp . '/sub/deep/c.txt', 'cccc');

idct_example_section('first upload — Overwrite (default)');
$first = $client->uploadDirectory($tmp, '/data/example-tree');
echo "uploaded {$first->filesTransferred} files, {$first->bytesTransferred} bytes, "
    . count($first->skipped) . " skipped, " . count($first->failures) . " failures.\n";

idct_example_section('second upload — Skip (idempotent)');
$second = $client->uploadDirectory(
    $tmp,
    '/data/example-tree',
    onConflict: ConflictPolicy::Skip,
);
echo "uploaded {$second->filesTransferred} files (expected 0), "
    . count($second->skipped) . " skipped (expected 3), "
    . count($second->failures) . " failures.\n";
echo "first 3 skipped paths:\n";
foreach (array_slice($second->skipped, 0, 3) as $p) {
    echo "  - {$p}\n";
}

idct_example_section('done — tree lives at /data/example-tree until example 06 wipes it');
foreach ($client->getFileList('/data/example-tree') as $name) {
    echo "  /data/example-tree/{$name}\n";
}

idct_example_section('cleanup local');
// Remove local fixture only; remote tree stays for example 06.
function rrmdir(string $p): void {
    if (is_dir($p)) {
        foreach (array_diff(scandir($p) ?: [], ['.', '..']) as $e) {
            rrmdir($p . '/' . $e);
        }
        rmdir($p);
    } elseif (file_exists($p)) {
        unlink($p);
    }
}
rrmdir($tmp);
$client->close();

echo "\ndone.\n";
