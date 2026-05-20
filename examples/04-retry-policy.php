<?php
/**
 * 04 — custom RetryPolicyInterface
 *
 * Replaces the default ExponentialBackoffRetryPolicy with one that
 * prints every retry decision, then triggers a transient failure on
 * the FIRST upload attempt only — the second attempt succeeds and the
 * file lands.
 *
 * The transient is simulated by wrapping the Ssh2FunctionsInterface
 * with a decorator that returns false for sftpRename on the first
 * call only. That matches the "Failed to copy local stream to remote
 * file: ... (rename of partial ...)" message that the retry allowlist
 * recognises as transient.
 */

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\Exception\SshException;
use IDCT\Networking\Ssh\Retry\RetryPolicyInterface;
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Ssh2\Ssh2Functions;
use IDCT\Networking\Ssh\Ssh2\Ssh2FunctionsInterface;

$verbosePolicy = new class implements RetryPolicyInterface {
    public function nextDelayMs(int $attempt, SshException $lastError): int
    {
        $delay = min(2_000, 50 * (2 ** ($attempt - 1)));
        echo "  retry decision: attempt={$attempt} delay={$delay}ms because="
            . $lastError::class . ': ' . $lastError->getMessage() . "\n";

        return $attempt > 3 ? 0 : $delay;
    }
};

$transientRename = new class (new Ssh2Functions()) implements Ssh2FunctionsInterface {
    private int $renameCallCount = 0;

    public function __construct(private Ssh2FunctionsInterface $inner) {}

    public function sftpRename(mixed $sftp, string $from, string $to): bool
    {
        $this->renameCallCount++;
        if ($this->renameCallCount === 1) {
            echo "  injecting transient sftpRename failure (call #1)\n";

            return false;
        }
        echo "  passing sftpRename through (call #{$this->renameCallCount})\n";

        return $this->inner->sftpRename($sftp, $from, $to);
    }

    public function connect(string $host, int $port, ?array $methods = null, ?array $callbacks = null): mixed
    { return $this->inner->connect($host, $port, $methods, $callbacks); }
    public function fingerprint(mixed $session, int $flags): string|false
    { return $this->inner->fingerprint($session, $flags); }
    public function authNone(mixed $session, string $username): bool
    { return $this->inner->authNone($session, $username); }
    public function authPassword(mixed $session, string $username, string $password): bool
    { return $this->inner->authPassword($session, $username, $password); }
    public function authPublicKey(mixed $session, string $username, string $publicKey, string $privateKey, ?string $passphrase = null): bool
    { return $this->inner->authPublicKey($session, $username, $publicKey, $privateKey, $passphrase); }
    public function sftp(mixed $session): mixed { return $this->inner->sftp($session); }
    public function sftpStat(mixed $sftp, string $path): array|false { return $this->inner->sftpStat($sftp, $path); }
    public function sftpMkdir(mixed $sftp, string $path, int $mode, bool $recursive): bool
    { return $this->inner->sftpMkdir($sftp, $path, $mode, $recursive); }
    public function sftpRmdir(mixed $sftp, string $path): bool { return $this->inner->sftpRmdir($sftp, $path); }
    public function sftpUnlink(mixed $sftp, string $path): bool { return $this->inner->sftpUnlink($sftp, $path); }
    public function scpRecv(mixed $session, string $remotePath, string $localPath): bool
    { return $this->inner->scpRecv($session, $remotePath, $localPath); }
    public function scpSend(mixed $session, string $localPath, string $remotePath, int $mode): bool
    { return $this->inner->scpSend($session, $localPath, $remotePath, $mode); }
    public function exec(mixed $session, string $command): mixed { return $this->inner->exec($session, $command); }
    public function disconnect(mixed $session): bool { return $this->inner->disconnect($session); }
    public function sftpStreamUri(mixed $sftp, string $path): string { return $this->inner->sftpStreamUri($sftp, $path); }
};

$s = idct_example_settings();
$client = new SftpClient(false, $transientRename, $verbosePolicy);
$client->setCredentials(Credentials::withPassword($s['user'], $s['pass']));
$client->connect($s['host'], $s['port']);

$tmp = sys_get_temp_dir() . '/idct-example-04-' . bin2hex(random_bytes(4));
mkdir($tmp);
$local = $tmp . '/transient.bin';
file_put_contents($local, "retried successfully");

idct_example_section('upload — expect 1 retry, then success');
$client->upload($local, '/data/example-04-transient.bin');
echo "upload completed.\n";

idct_example_section('cleanup');
$client->remove('/data/example-04-transient.bin');
unlink($local);
rmdir($tmp);
$client->close();

echo "\ndone.\n";
