<?php
/**
 * 07 — uploadStream from an S3 (minio) HTTP source
 *
 * Bring up the fixture with `tests/functional/bin/up`; the `minio-init`
 * one-shot container pre-seeds an anonymous-read bucket containing
 * `payload.bin` with the bytes "streamed-from-minio-s3-payload".
 *
 * This script:
 *   1. fopen()s the minio HTTP URL (non-seekable stream).
 *   2. Pipes it into SftpClient::uploadStream — chunked copy, atomic
 *      rename onto the destination.
 *   3. Downloads the destination back and prints what landed.
 *
 * For a real S3 source via aws/aws-sdk-php:
 *
 *     $body = $s3->getObject(['Bucket' => 'b', 'Key' => 'k'])
 *                ->get('Body');
 *     $stream = $body->detach(); // returns a PHP stream resource
 *     $client->uploadStream($stream, '/remote/dest.bin');
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

$minioUrl = getenv('MINIO_URL') !== false
    ? (string) getenv('MINIO_URL')
    : 'http://127.0.0.1:9000/idct-test/payload.bin';

$client = idct_example_client();

idct_example_section("open HTTP stream from minio ({$minioUrl})");
$stream = @fopen($minioUrl, 'rb');
if ($stream === false) {
    fwrite(STDERR, "Could not open {$minioUrl} — is the minio fixture running?\n");
    fwrite(STDERR, "Run `tests/functional/bin/up` from the repo root.\n");
    exit(1);
}
echo "stream opened.\n";

idct_example_section('uploadStream to /data/example-07-from-s3.bin');
$client->uploadStream($stream, '/data/example-07-from-s3.bin');
fclose($stream);
echo "uploadStream returned.\n";

idct_example_section('downloadStream into php://temp + dump');
$sink = fopen('php://temp/maxmemory:0', 'r+b');
$bytes = $client->downloadStream('/data/example-07-from-s3.bin', $sink);
rewind($sink);
echo "downloaded {$bytes} bytes:\n  " . trim((string) stream_get_contents($sink)) . "\n";
fclose($sink);

idct_example_section('cleanup');
$client->remove('/data/example-07-from-s3.bin');
$client->close();

echo "\ndone.\n";
