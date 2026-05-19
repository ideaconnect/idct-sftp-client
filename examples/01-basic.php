<?php
/**
 * 01 — basic round-trip
 *
 * Connect, upload a small file, download it back, verify byte-identity,
 * clean up. The simplest possible end-to-end use of SftpClient.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

$client = idct_example_client();

$tmp = sys_get_temp_dir() . '/idct-example-01-' . bin2hex(random_bytes(4));
mkdir($tmp);
$local = $tmp . '/hello.txt';
$payload = "hello from example 01 — " . date('c');
file_put_contents($local, $payload);

idct_example_section('upload');
$client->upload($local, '/data/example-01-hello.txt');
echo "uploaded " . strlen($payload) . " bytes to /data/example-01-hello.txt\n";

idct_example_section('download');
$roundtrip = $tmp . '/hello-roundtrip.txt';
$client->download('/data/example-01-hello.txt', $roundtrip);
echo "downloaded into {$roundtrip}\n";

idct_example_section('verify');
$got = file_get_contents($roundtrip);
echo ($got === $payload) ? "bytes match — OK\n" : "BYTES DIFFER — FAIL\n";

idct_example_section('cleanup');
$client->remove('/data/example-01-hello.txt');
unlink($local);
unlink($roundtrip);
rmdir($tmp);
$client->close();

echo "\ndone.\n";
