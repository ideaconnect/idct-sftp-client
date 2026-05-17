<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Exception;

/**
 * Root of every exception thrown by this library.
 *
 * Catch this to handle anything the SFTP client can raise:
 *
 *     try {
 *         $client->upload($src, $dest);
 *     } catch (SshException $e) {
 *         // any failure originating from idct/sftp-client
 *     }
 *
 * Concrete subclasses (AuthenticationException, ConfigurationException,
 * ConnectionException, RemoteFilesystemException, TransferException,
 * InvalidPathException) let callers narrow when they need to react
 * differently to different failure modes.
 */
abstract class SshException extends \RuntimeException {}
