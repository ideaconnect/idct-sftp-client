<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Invalid caller-provided configuration: missing credentials, bad
 * authentication mode, key file that doesn't exist, malformed path, etc.
 * Caught before any network I/O happens.
 */
class ConfigurationException extends SshException {}
