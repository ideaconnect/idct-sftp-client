<?php
include "../vendor/autoload.php";
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Credentials;
use IDCT\Networking\Ssh\AuthMode;
use PHPUnit\Framework\TestCase;

/**
 * Script used by my (author) to verify functionality.
 *
 * Uses credentials from /etc/secrets.php
 *
 * Example:
 * $sftpClient_test = [
 *    'host' => 'idct.pl',
 *    'user' => 'username',
 *    'key' => '/home/youruser/.ssh/id_rsa',
 *    'testfile' => '/tmp/testfile.1'
 *  ];
 */

//Load /etc/secrets.php
if (!file_exists('/etc/secrets.php')) {
    throw new Exception('/etc/secrets.php not readable!');
}

include '/etc/secrets.php';
$host = $sftpClient_test['host'];
$user = $sftpClient_test['user'];
$key = $sftpClient_test['key'];
$testfile = $sftpClient_test['testfile'];
$testfileName = basename($testfile);

$time = time();
$credentials = new Credentials();
$credentials = Credentials::withPublicKey($user, $key . '.pub', $key);

$client = new SftpClient(true);
$client->setCredentials($credentials);
$client->connect($host);


$client->makeDirectory('/tmp/test/inner/', 0777, true)
       ->setRemotePrefix('/tmp/test/inner/')
       ->setLocalPrefix('')
       ->upload($testfile)
       ;

$files = $client->getFileList('/tmp/test/inner/');
if (count($files) < 3) {
    throw new Exception('[FAIL] File count should be equal to 3.');
}

@unlink('/tmp/' . $testfileName . '.2');
$client->setLocalPrefix('/tmp/')
       ->rename($testfileName, '/tmp/test/inner/' . $testfileName . '.2')
       ->download('/tmp/test/inner/' . $testfileName . '.2')
       ;

if (!file_exists('/tmp/'. $testfileName . '.2')) {
    throw new Exception('[FAIL] Downloaded file not present.');
}

$client->remove($testfileName . '.2');
if ($client->fileExists($client->getRemotePrefix() . $testfileName . '.2' )) {
    throw new Exception('[FAIL] Remote file not removed.');
}

$client->removeDirectory('/tmp/test/inner/');
if ($client->fileExists('/tmp/test/inner/')) {
    throw new Exception('[FAIL] Remote dir not removed.');
}

$client->removeDirectory('/tmp/test/');
if ($client->fileExists('/tmp/test/')) {
    throw new Exception('[FAIL] Remote dir not removed.');
}

$client->close();

echo "[OK!]" . PHP_EOL;
