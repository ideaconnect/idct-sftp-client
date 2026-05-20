<?php
/**
 * 06 — walk() a remote tree, then removeDirectoryTree()
 *
 * Picks up where example 05 left off: walks /data/example-tree in
 * post-order, prints each entry, then removes the whole tree.
 *
 * Safe to run even if 05 didn't run — getFileList will return empty
 * and walk yields zero entries.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use IDCT\Networking\Ssh\Exception\RemoteFilesystemException;

$client = idct_example_client();

idct_example_section('walk() /data/example-tree (post-order: children before parent)');
try {
    foreach ($client->walk('/data/example-tree') as $entry) {
        $size = $entry->size === null ? '-' : (string) $entry->size;
        printf("  %-13s  %5s  %s\n", $entry->type->name, $size, $entry->path);
    }
} catch (RemoteFilesystemException $e) {
    echo "  (nothing to walk — example 05 hasn't run yet?)\n";
}

idct_example_section('removeDirectoryTree() — wipe the whole subtree');
try {
    $client->removeDirectoryTree('/data/example-tree');
    echo "removed /data/example-tree\n";
} catch (RemoteFilesystemException $e) {
    echo "removal skipped: " . $e->getMessage() . "\n";
}

$client->close();
echo "\ndone.\n";
