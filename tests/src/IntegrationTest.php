<?php

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Credentials;
use IDCT\Networking\Ssh\AuthMode;
use PHPUnit\Framework\TestCase;

/**
 * Script used by my (author) to verify functionality.
 *
 * Uses credentials from /etc/secrets.php
 */

//Load /etc/secrets.php
if (!file_exists('/etc/secrets.php')) {
    throw new Exception('/etc/secrets.php not readable!');
}

include '/etc/secrets.php';
$host = $sftpClient_test['host'];
$user = $sftpClient_test['user'];
$password = $sftpClient_test['password'];
