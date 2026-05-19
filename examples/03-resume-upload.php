<?php
/**
 * 03 — resume an interrupted upload
 *
 * Walkthrough:
 *  1. Start an upload but abort it half-way (we simulate this by
 *     uploading the first half directly to the deterministic
 *     `.{basename}.resume` sibling).
 *  2. Call resumeUpload() — it stats the partial, picks up at byte N,
 *     appends the rest, then renames onto the final path.
 *  3. Download + verify byte-identity.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

$client = idct_example_client();

$tmp = sys_get_temp_dir() . '/idct-example-03-' . bin2hex(random_bytes(4));
mkdir($tmp);
$local = $tmp . '/full-payload.bin';
$payload = random_bytes(64 * 1024); // 64 KiB
file_put_contents($local, $payload);

$remoteFinal = '/data/example-03-payload.bin';
$remotePartial = '/data/.example-03-payload.bin.resume';

idct_example_section('simulate aborted upload (first half lands as partial)');
$halfFile = $tmp . '/half-payload.bin';
file_put_contents($halfFile, substr($payload, 0, 32 * 1024));
// Upload the half-file directly into the partial path; turn atomic off
// so it lands at that name verbatim.
$client->disableAtomicUploads();
$client->upload($halfFile, $remotePartial);
$client->enableAtomicUploads();
echo "partial seeded: 32 KiB at {$remotePartial}\n";

idct_example_section('resume the upload — auto-detect offset');
$client->resumeUpload($local, $remoteFinal);
echo "resumeUpload returned; final path should now hold the full 64 KiB\n";

idct_example_section('verify byte-identity');
$dl = $tmp . '/roundtrip.bin';
$client->download($remoteFinal, $dl);
$got = file_get_contents($dl);
echo ($got === $payload)
    ? "bytes match (length=" . strlen($got) . ") — OK\n"
    : "BYTES DIFFER — FAIL (length=" . strlen($got) . " vs " . strlen($payload) . ")\n";

idct_example_section('cleanup');
$client->remove($remoteFinal);
unlink($local);
unlink($halfFile);
unlink($dl);
rmdir($tmp);
$client->close();

echo "\ndone.\n";
