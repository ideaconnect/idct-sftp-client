<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Thrown by {@see \IDCT\Networking\Ssh\Path\PathValidator} when a remote path
 * argument is rejected (null byte, control character, path traversal,
 * length overflow, absolute-when-disallowed).
 *
 * Extends {@see ConfigurationException} so the single-parent rule holds —
 * `catch (SshException $e)` picks it up like every other exception this
 * library throws, and `catch (ConfigurationException $e)` picks it up
 * alongside other "caller supplied bad input" failures.
 */
final class InvalidPathException extends ConfigurationException {}
