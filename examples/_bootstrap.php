<?php

declare(strict_types=1);

/**
 * Shared bootstrap for the examples — composer autoload, env-derived
 * connection settings, and a connected SftpClient factory.
 *
 * Each example does:
 *
 *   require __DIR__ . '/_bootstrap.php';
 *   $client = idct_example_client();
 */

require __DIR__ . '/../vendor/autoload.php';

use IDCT\Networking\Ssh\Auth\Credentials;
use IDCT\Networking\Ssh\SftpClient;

function idct_example_settings(): array
{
    return [
        'host' => getenv('SFTP_HOST') !== false ? (string) getenv('SFTP_HOST') : '127.0.0.1',
        'port' => getenv('SFTP_PORT') !== false ? (int) getenv('SFTP_PORT') : 2222,
        'user' => getenv('SFTP_USER') !== false ? (string) getenv('SFTP_USER') : 'tester',
        'pass' => getenv('SFTP_PASS') !== false ? (string) getenv('SFTP_PASS') : 'testerpass',
    ];
}

function idct_example_client(): SftpClient
{
    $s = idct_example_settings();
    $client = new SftpClient();
    $client->setCredentials(Credentials::withPassword($s['user'], $s['pass']));
    $client->connect($s['host'], $s['port']);

    return $client;
}

function idct_example_section(string $label): void
{
    echo "\n=== {$label} ===\n";
}
