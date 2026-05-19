<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\KnownHosts;

use IDCT\Networking\Ssh\Exception\ConfigurationException;

/**
 * Parse and query an OpenSSH-compatible `known_hosts` file.
 *
 * Supported entry forms:
 *
 *  - Plain comma-separated hostnames: `example.com,93.184.216.34 ssh-rsa AAAA...`
 *  - Port-qualified hostnames:        `[example.com]:2222 ssh-ed25519 AAAA...`
 *  - Hashed hostnames:                `|1|base64salt|base64hash ssh-rsa AAAA...`
 *  - Custom TOFU entries written by {@see appendFingerprint()}:
 *                                     `example.com sha1-fpr <lowerHexFingerprint>`
 *
 * ## Why SHA-1 rather than SHA-256
 *
 * libssh2's `SSH2_FINGERPRINT_SHA256` constant is only defined in newer
 * builds (libssh2 1.9+). The library ships against `ext-ssh2 >= 1.4` so we
 * fall back to SHA-1, which has been in libssh2 since 0.x and is still
 * acceptable for fingerprint comparison (no practical preimage attack on
 * an arbitrary 256-bit SSH key blob). Standard OpenSSH known_hosts entries
 * store the full key blob, so when we read one we compute SHA-1 of the
 * decoded blob and compare against the server's SHA-1 fingerprint — both
 * sides see the same algorithm.
 *
 * Not supported (silently skipped):
 *
 *  - `@cert-authority` and `@revoked` markers
 *  - Negated hostnames (`!host` inside an entry)
 *  - Wildcard hostnames (`*.example.com`, `?`)
 *
 * Malformed lines are skipped rather than rejected — the OpenSSH client
 * behaves the same way, and forcing a hard parse error on a single bad
 * line would break connect() for unrelated hosts.
 *
 * ## Fingerprint format
 *
 * The fingerprint passed to {@see verifyHost()} and
 * {@see appendFingerprint()} must be lowercase-hex SHA-1 of the SSH key
 * blob, with no `SHA1:` prefix and no `:` separators — i.e. the format
 * returned by `ssh2_fingerprint($session, SSH2_FINGERPRINT_SHA1 |
 * SSH2_FINGERPRINT_HEX)` after a `strtolower()` pass.
 *
 * @phpstan-type ParsedEntry array{
 *     hashed: bool,
 *     hashSalt?: string,
 *     hashHash?: string,
 *     hostnames?: list<string>,
 *     keytype: string,
 *     keydata: string
 * }
 */
final class KnownHostsFile
{
    /** @var list<ParsedEntry> */
    private array $entries;

    /** Path the file was loaded from; the same path is used by appendFingerprint(). */
    private readonly string $path;

    /**
     * @throws ConfigurationException when the path exists but cannot be read
     */
    public function __construct(string $path)
    {
        $this->path = $path;
        $this->entries = self::parseFile($path);
    }

    /**
     * Compare a server fingerprint against entries matching `$host`/`$port`.
     */
    public function verifyHost(string $host, int $port, string $serverFingerprintHex): HostKeyDecision
    {
        $needle = strtolower($serverFingerprintHex);
        $hostMatched = false;

        foreach ($this->entries as $entry) {
            if (! $this->entryCoversHost($entry, $host, $port)) {
                continue;
            }
            $hostMatched = true;
            if (hash_equals($needle, $this->entryFingerprint($entry))) {
                return HostKeyDecision::Trusted;
            }
        }

        return $hostMatched ? HostKeyDecision::Mismatch : HostKeyDecision::NoEntries;
    }

    /**
     * Append a TOFU entry recording `$serverFingerprintHex` as trusted for
     * `$host` / `$port`. Creates the file (mode 0600) if it doesn't exist.
     * Updates the in-memory entry set so subsequent verifyHost() calls on
     * the same instance also see it.
     *
     * @throws ConfigurationException on filesystem permission failures
     */
    public function appendFingerprint(string $host, int $port, string $serverFingerprintHex): void
    {
        $hostspec = self::hostspec($host, $port);
        $line = $hostspec . ' sha1-fpr ' . strtolower($serverFingerprintHex);

        // If the file doesn't exist, create with strict perms so a stray
        // umask doesn't leave the fingerprint store world-readable.
        if (! is_file($this->path)) {
            $dir = \dirname($this->path);
            if (! is_dir($dir) && ! @mkdir($dir, 0o700, true) && ! is_dir($dir)) {
                throw new ConfigurationException(
                    'Could not create directory for known_hosts file: ' . $dir,
                );
            }
            if (@file_put_contents($this->path, $line . "\n", LOCK_EX) === false) {
                throw new ConfigurationException('Could not write known_hosts file: ' . $this->path);
            }
            @chmod($this->path, 0o600);
        } else {
            // Make sure we land on a fresh line even if the existing file
            // doesn't end with one.
            $needsNewline = @filesize($this->path) > 0
                && @file_get_contents($this->path, length: 1, offset: max(0, (int) filesize($this->path) - 1)) !== "\n";
            $payload = ($needsNewline ? "\n" : '') . $line . "\n";
            if (@file_put_contents($this->path, $payload, FILE_APPEND | LOCK_EX) === false) {
                throw new ConfigurationException('Could not append to known_hosts file: ' . $this->path);
            }
        }

        $this->entries[] = [
            'hashed' => false,
            'hostnames' => [$hostspec],
            'keytype' => 'sha1-fpr',
            'keydata' => strtolower($serverFingerprintHex),
        ];
    }

    /**
     * Compose the hostspec OpenSSH would use for this host:port pair.
     * Port 22 → bare host; any other port → `[host]:port`.
     */
    private static function hostspec(string $host, int $port): string
    {
        return $port === 22 ? $host : '[' . $host . ']:' . $port;
    }

    /**
     * Does the entry cover this host? Handles both the plain-hostnames
     * and the hashed forms.
     *
     * @param ParsedEntry $entry
     */
    private function entryCoversHost(array $entry, string $host, int $port): bool
    {
        $candidate = self::hostspec($host, $port);
        $candidateLc = strtolower($candidate);

        if ($entry['hashed'] === false) {
            foreach ($entry['hostnames'] ?? [] as $name) {
                if (strtolower($name) === $candidateLc) {
                    return true;
                }
            }

            return false;
        }

        // Hashed: HMAC-SHA1(salt, candidate-as-stored).
        $salt = base64_decode($entry['hashSalt'] ?? '', true);
        $hash = base64_decode($entry['hashHash'] ?? '', true);
        if ($salt === false || $hash === false) {
            return false;
        }
        $computed = hash_hmac('sha1', $candidate, $salt, true);

        return hash_equals($hash, $computed);
    }

    /**
     * Derive the entry's lowercase-hex SHA-256 fingerprint for comparison.
     * For standard `ssh-*` / `ecdsa-*` entries this is sha256(base64-decoded keydata).
     * For our custom `sha1-fpr` entries the keydata IS the hex fingerprint.
     *
     * @param ParsedEntry $entry
     */
    private function entryFingerprint(array $entry): string
    {
        if ($entry['keytype'] === 'sha1-fpr') {
            return strtolower($entry['keydata']);
        }

        $raw = base64_decode($entry['keydata'], true);
        if ($raw === false) {
            return '';
        }

        return strtolower(bin2hex(hash('sha1', $raw, true)));
    }

    /**
     * @return list<ParsedEntry>
     */
    private static function parseFile(string $path): array
    {
        if (! is_file($path)) {
            // Missing file: zero entries. verifyHost() will return NoEntries
            // for every host; appendFingerprint() creates it on demand.
            return [];
        }
        $body = @file_get_contents($path);
        if ($body === false) {
            throw new ConfigurationException('Could not read known_hosts file: ' . $path);
        }

        $entries = [];
        $lines = preg_split('/\R/', $body);
        foreach ($lines === false ? [] : $lines as $raw) {
            $line = trim($raw);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            // Skip @cert-authority / @revoked markers for the first cut —
            // not enforcing them is the existing behaviour of zero-config
            // libssh2 clients.
            if (str_starts_with($line, '@')) {
                continue;
            }
            $parts = preg_split('/\s+/', $line, 3);
            if ($parts === false || \count($parts) < 3) {
                continue;
            }
            [$hostspec, $keytype, $keydata] = $parts;
            // Keydata field may carry a trailing comment ("keytype keydata
            // optional comment ..."); split once to extract just the keydata.
            // The empty-keydata case is unreachable — the outer trim($raw) +
            // 3-token count check above already filtered lines that lack a
            // keydata token entirely.
            $keydataParts = preg_split('/\s+/', trim($keydata), 2);
            $keydata = $keydataParts === false ? $keydata : $keydataParts[0];
            $entry = self::parseHostspec($hostspec, $keytype, $keydata);
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return ParsedEntry|null null if the entry can't be classified
     *                          (e.g. negation-only hostspec)
     */
    private static function parseHostspec(string $hostspec, string $keytype, string $keydata): ?array
    {
        if (str_starts_with($hostspec, '|1|')) {
            // Hashed: |1|<salt>|<hash>
            $bits = explode('|', $hostspec);
            // ['', '1', '<salt>', '<hash>']
            if (\count($bits) !== 4 || $bits[2] === '' || $bits[3] === '') {
                return null;
            }

            return [
                'hashed' => true,
                'hashSalt' => $bits[2],
                'hashHash' => $bits[3],
                'keytype' => $keytype,
                'keydata' => $keydata,
            ];
        }

        $names = [];
        foreach (explode(',', $hostspec) as $name) {
            $name = trim($name);
            if ($name === '' || str_starts_with($name, '!')) {
                // Negation entries are skipped — supporting them needs the
                // "match wins unless any negation matches" rule, which the
                // wildcard pass would also need. Both are future work.
                continue;
            }
            $names[] = $name;
        }
        if ($names === []) {
            return null;
        }

        return [
            'hashed' => false,
            'hostnames' => $names,
            'keytype' => $keytype,
            'keydata' => $keydata,
        ];
    }
}
