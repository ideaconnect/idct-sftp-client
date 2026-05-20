<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Tests\KnownHosts;

use IDCT\Networking\Ssh\Exception\ConfigurationException;
use IDCT\Networking\Ssh\KnownHosts\HostKeyDecision;
use IDCT\Networking\Ssh\KnownHosts\KnownHostsFile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the OpenSSH `known_hosts` parser + TOFU appender. Builds
 * small fixture files in a per-test tmpdir; no SSH server involved.
 *
 * Test fingerprints are 40-char lowercase hex (the format the library uses
 * after `ssh2_fingerprint($session, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX)`).
 */
#[CoversClass(KnownHostsFile::class)]
#[UsesClass(HostKeyDecision::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\ConfigurationException::class)]
#[UsesClass(\IDCT\Networking\Ssh\Exception\SshException::class)]
final class KnownHostsFileTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/idct-known-hosts-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0o700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmpDir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->tmpDir);
    }

    // ─── parsing ────────────────────────────────────────────────────────

    public function testEmptyFileVerifiesAsNoEntries(): void
    {
        $path = $this->tmpDir . '/empty';
        file_put_contents($path, '');

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::NoEntries,
            $f->verifyHost('example.com', 22, str_repeat('a', 40)),
        );
    }

    public function testMissingFileVerifiesAsNoEntries(): void
    {
        $f = new KnownHostsFile($this->tmpDir . '/does-not-exist');
        self::assertSame(
            HostKeyDecision::NoEntries,
            $f->verifyHost('example.com', 22, str_repeat('a', 40)),
        );
    }

    public function testParserSkipsCommentsBlankLinesAndMarkers(): void
    {
        $path = $this->tmpDir . '/mixed';
        file_put_contents($path, implode("\n", [
            '# this is a comment',
            '',
            '   # indented comment',
            '@cert-authority *.example.com ssh-rsa AAAA',
            '@revoked attacker.example.com ssh-rsa AAAA',
            'example.com sha1-fpr ' . str_repeat('b', 40),
            '',
        ]));

        // Only the sha1-fpr entry should have been kept; verifyHost finds it.
        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::Trusted,
            $f->verifyHost('example.com', 22, str_repeat('b', 40)),
        );
    }

    public function testParserSkipsMalformedLines(): void
    {
        $path = $this->tmpDir . '/malformed';
        file_put_contents($path, implode("\n", [
            'short',                                              // too few tokens
            'two tokens',                                         // still too few
            'host keytype',                                       // missing keydata
            'host keytype  ',                                     // 3 tokens, keydata empty after strip
            'example.com sha1-fpr ' . str_repeat('c', 40),      // valid entry survives
        ]));

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::Trusted,
            $f->verifyHost('example.com', 22, str_repeat('c', 40)),
        );
    }

    public function testCommaSeparatedHostnamesMatchEither(): void
    {
        $path = $this->tmpDir . '/multi-host';
        $fp = str_repeat('d', 40);
        file_put_contents(
            $path,
            'alpha.example.com,beta.example.com,93.184.216.34 sha1-fpr ' . $fp . "\n",
        );

        $f = new KnownHostsFile($path);
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('alpha.example.com', 22, $fp));
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('beta.example.com', 22, $fp));
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('93.184.216.34', 22, $fp));
        self::assertSame(HostKeyDecision::NoEntries, $f->verifyHost('gamma.example.com', 22, $fp));
    }

    public function testNegationEntriesAreSkippedForFirstCut(): void
    {
        // Entry with ONLY negation patterns leaves the hostlist empty → entry dropped.
        $path = $this->tmpDir . '/negation';
        file_put_contents(
            $path,
            '!attacker.example.com sha1-fpr ' . str_repeat('e', 40) . "\n",
        );

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::NoEntries,
            $f->verifyHost('attacker.example.com', 22, str_repeat('e', 40)),
        );
    }

    public function testPortQualifiedHostspecMatchesNonDefaultPortOnly(): void
    {
        $path = $this->tmpDir . '/port';
        $fp = str_repeat('f', 40);
        file_put_contents(
            $path,
            '[example.com]:2222 sha1-fpr ' . $fp . "\n",
        );

        $f = new KnownHostsFile($path);
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('example.com', 2222, $fp));
        // Port 22 is bare-host form — the [host]:2222 entry shouldn't match it.
        self::assertSame(HostKeyDecision::NoEntries, $f->verifyHost('example.com', 22, $fp));
    }

    // ─── verifyHost decisions ──────────────────────────────────────────

    public function testMismatchWhenHostKnownButFingerprintDiffers(): void
    {
        $path = $this->tmpDir . '/mismatch';
        file_put_contents(
            $path,
            'example.com sha1-fpr ' . str_repeat('a', 40) . "\n",
        );

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::Mismatch,
            $f->verifyHost('example.com', 22, str_repeat('b', 40)),
        );
    }

    public function testFingerprintComparisonIsCaseInsensitive(): void
    {
        $path = $this->tmpDir . '/case';
        $lower = str_repeat('a', 40);
        $upper = strtoupper($lower);
        file_put_contents($path, 'example.com sha1-fpr ' . $upper . "\n");

        $f = new KnownHostsFile($path);
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('example.com', 22, $lower));
    }

    public function testStandardSshRsaEntryFingerprintMatch(): void
    {
        // Compute the SHA-1 of an arbitrary key byte string and put its
        // base64 form in a synthetic ssh-rsa entry. The parser computes
        // sha1(base64-decode(keydata)) hex-lower and compares — same as
        // older ssh-keygen -E sha1 -lf known_hosts would print.
        $keyBlob = random_bytes(64);
        $expectedFp = bin2hex(hash('sha1', $keyBlob, true));
        $entry = 'example.com ssh-rsa ' . base64_encode($keyBlob);
        $path = $this->tmpDir . '/rsa';
        file_put_contents($path, $entry . "\n");

        $f = new KnownHostsFile($path);
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('example.com', 22, $expectedFp));
        self::assertSame(HostKeyDecision::Mismatch, $f->verifyHost('example.com', 22, str_repeat('0', 40)));
    }

    public function testStandardEntryWithMalformedKeydataReturnsEmptyFingerprint(): void
    {
        // Invalid base64 in the keydata field — entryFingerprint() returns ''
        // and any real server fingerprint won't match it → Mismatch (because
        // the host IS present).
        $path = $this->tmpDir . '/broken-keydata';
        file_put_contents($path, "example.com ssh-rsa \x21\x21not-base64\n");

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::Mismatch,
            $f->verifyHost('example.com', 22, str_repeat('a', 40)),
        );
    }

    // ─── hashed hostnames ──────────────────────────────────────────────

    public function testHashedHostnameMatches(): void
    {
        $host = 'example.com';
        $salt = random_bytes(20);
        $hash = hash_hmac('sha1', $host, $salt, true);
        $hashedSpec = '|1|' . base64_encode($salt) . '|' . base64_encode($hash);
        $fp = str_repeat('a', 40);

        $path = $this->tmpDir . '/hashed';
        file_put_contents($path, $hashedSpec . ' sha1-fpr ' . $fp . "\n");

        $f = new KnownHostsFile($path);
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost($host, 22, $fp));
        // Wrong host gets no match → NoEntries (the entry didn't cover the host).
        self::assertSame(HostKeyDecision::NoEntries, $f->verifyHost('other.com', 22, $fp));
    }

    public function testHashedEntryWithBrokenSaltOrHashIsSkipped(): void
    {
        $path = $this->tmpDir . '/bad-hashed';
        file_put_contents($path, implode("\n", [
            // Broken salt base64
            '|1|!!!|' . base64_encode(random_bytes(20)) . ' sha1-fpr ' . str_repeat('a', 40),
            // Broken hash base64
            '|1|' . base64_encode(random_bytes(16)) . '|!!! sha1-fpr ' . str_repeat('a', 40),
            // Wrong field count
            '|1|onlysalt sha1-fpr ' . str_repeat('a', 40),
            // Empty salt
            '|1||' . base64_encode(random_bytes(20)) . ' sha1-fpr ' . str_repeat('a', 40),
            // Empty hash
            '|1|' . base64_encode(random_bytes(16)) . '| sha1-fpr ' . str_repeat('a', 40),
        ]));

        $f = new KnownHostsFile($path);
        self::assertSame(
            HostKeyDecision::NoEntries,
            $f->verifyHost('example.com', 22, str_repeat('a', 40)),
        );
    }

    // ─── appendFingerprint ─────────────────────────────────────────────

    public function testAppendFingerprintCreatesFileWithStrictPerms(): void
    {
        $path = $this->tmpDir . '/sub/new-known-hosts';
        $f = new KnownHostsFile($path);
        $fp = str_repeat('1', 40);

        $f->appendFingerprint('example.com', 22, $fp);

        self::assertFileExists($path);
        self::assertStringContainsString('example.com sha1-fpr ' . $fp, file_get_contents($path));
        // The in-memory entries should now find the fingerprint.
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('example.com', 22, $fp));
        // File mode trimmed to 0600 on creation.
        self::assertSame('600', substr(sprintf('%o', fileperms($path) & 0o777), -3));
    }

    public function testAppendFingerprintEncodesPortInBrackets(): void
    {
        $path = $this->tmpDir . '/with-port';
        $f = new KnownHostsFile($path);
        $fp = str_repeat('2', 40);

        $f->appendFingerprint('example.com', 2222, $fp);

        self::assertStringContainsString(
            '[example.com]:2222 sha1-fpr ' . $fp,
            file_get_contents($path),
        );
        self::assertSame(HostKeyDecision::Trusted, $f->verifyHost('example.com', 2222, $fp));
    }

    public function testAppendFingerprintAddsLeadingNewlineWhenFileDoesntEndOne(): void
    {
        $path = $this->tmpDir . '/no-trailing-nl';
        file_put_contents($path, 'first.example.com sha1-fpr ' . str_repeat('1', 40));
        // No trailing newline above.

        $f = new KnownHostsFile($path);
        $f->appendFingerprint('second.example.com', 22, str_repeat('2', 40));

        $body = file_get_contents($path);
        // Each entry should be on its own line — count newlines = 2 entries.
        self::assertSame(2, substr_count($body, "\n"));
        self::assertStringContainsString('first.example.com', $body);
        self::assertStringContainsString('second.example.com', $body);
    }

    public function testAppendFingerprintRaisesWhenParentDirCannotBeCreated(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }
        $ro = $this->tmpDir . '/ro-parent';
        mkdir($ro, 0o500); // r-x, mkdir of a subdir will fail

        try {
            $path = $ro . '/new-subdir/known_hosts';
            $f = new KnownHostsFile($path);
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('Could not create directory for known_hosts file');
            $f->appendFingerprint('example.com', 22, str_repeat('a', 40));
        } finally {
            chmod($ro, 0o700);
        }
    }

    public function testAppendFingerprintRaisesOnWriteFailure(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a directory unwritable to root.');
        }
        $ro = $this->tmpDir . '/ro';
        mkdir($ro, 0o500); // r-x — chmod denies write

        try {
            $path = $ro . '/known_hosts';
            $f = new KnownHostsFile($path);
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('Could not write known_hosts file');
            $f->appendFingerprint('example.com', 22, str_repeat('a', 40));
        } finally {
            chmod($ro, 0o700);
        }
    }

    public function testAppendFingerprintRaisesWhenAppendFails(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a file unwritable to root.');
        }
        $path = $this->tmpDir . '/locked';
        file_put_contents($path, "first.example.com sha1-fpr " . str_repeat('1', 40) . "\n");
        chmod($path, 0o400); // read-only

        try {
            $f = new KnownHostsFile($path);
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('Could not append to known_hosts file');
            $f->appendFingerprint('second.example.com', 22, str_repeat('2', 40));
        } finally {
            chmod($path, 0o600);
        }
    }

    public function testConstructorRaisesWhenFileIsUnreadable(): void
    {
        if (posix_getuid() === 0) {
            self::markTestSkipped('Cannot make a file unreadable to root.');
        }
        $path = $this->tmpDir . '/locked-read';
        file_put_contents($path, "example.com sha1-fpr " . str_repeat('1', 40) . "\n");
        chmod($path, 0o000);

        try {
            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('Could not read known_hosts file');
            new KnownHostsFile($path);
        } finally {
            chmod($path, 0o600);
        }
    }
}
