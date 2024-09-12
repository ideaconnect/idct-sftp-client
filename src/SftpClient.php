<?php

namespace IDCT\Networking\Ssh;

use Exception as Exception;

/**
 * SFTP Client for PHP
 *
 * @package SftpClient
 * @version 1.0
 *
 * @copyright Bartosz Pachołek
 * @copyleft Bartosz pachołek
 * @author Bartosz Pachołek

 * @license http://opensource.org/licenses/MIT (The MIT License)
 *
 * Copyright (c) 2014, IDCT IdeaConnect Bartosz Pachołek (https://idct.pl/)
 * Copyleft (c) 2014, IDCT IdeaConnect Bartosz Pachołek (https://idct.pl/)
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
class SftpClient
{
    /**
     * Credentials used for authorization of the connection.
     *
     * @var Credentials
     */
    protected $credentials;

    /**
     * Sftp resource created by ssh2_sftp for use with all sftp methods.
     *
     * @var Resource
     */
    protected $sftpResource;

    /**
     * Ssh connection resource created by ssh2_connect for use with all ssh methods.
     *
     * @var Resource
     */
    protected $sshResource;

    /**
     * Path prefix used for saving in the local file system.
     * With trailing slash!
     *
     * @var string
     */
    protected $localPrefix = ''; //with the trailing slash

    /**
     * Path prefix used for saving in the remote file system.
     * With trailing slash!
     *
     * @var string
     */
    protected $remotePrefix = ''; //with the trailing slash

    /**
     * If enabled verifies each file for same file size.
     *
     * @var boolean
     */
    protected $fileSizeVerificationEnabled = false;

    /**
     * Host.
     *
     * @var string
     */
    protected $host;

    /**
     * Port.
     *
     * @var int
     */
    protected $port;

    /**
     * Constructor.
     *
     * Checks if ssh2 extension is loaded.
     */
    public function __construct($enableFileSizeVerification = false)
    {
        if (!extension_loaded('ssh2')) {
            throw new Exception('Ssh2 extension is not loaded!');
        }

        if ($enableFileSizeVerification) {
            $this->enableFileSizeVerification();
        }

        return $this;
    }

    public function __destruct()
    {
        $this->Close();
    }

    /**
     * Enables file size verification.
     *
     * @return $this
     */
    public function enableFileSizeVerification()
    {
        $this->fileSizeVerificationEnabled = true;

        return $this;
    }

    /**
     * Disables file size verification.
     *
     * @return $this
     */
    public function disableFileSizeVerification()
    {
        $this->fileSizeVerificationEnabled = false;

        return $this;
    }

    /**
     * Setter for the credentials used for authorization.
     *
     * @param Credentials $credentials Credentials object used for authorization
     * @return $this
     */
    public function setCredentials(Credentials $credentials)
    {
        $this->credentials = $credentials;

        return $this;
    }

    /**
     * Getter of assigned authorization credentials object.
     *
     * @return Credentials|null
     */
    public function getCredentials()
    {
        return $this->credentials;
    }

    /**
     * Sets the prefix used for saving of files in the local file system.
     * Please follow phpDoc of upload, remove and download methods to understand
     * when in use.
     *
     * @param string $prefix Prefix used for saving of files in the local file system
     * @return $this
     */
    public function setLocalPrefix($prefix)
    {
        if (is_null($prefix)) {
            $prefix = '';
        }
        $this->localPrefix = $prefix;

        return $this;
    }

    /**
     * Gets the prefix used for saving of files in the local file system.
     * Please follow phpDoc of upload, remove and download methods to understand
     * when in use.
     *
     * @return string
     */
    public function getLocalPrefix()
    {
        return $this->localPrefix;
    }

    /**
     * Sets the prefix used for saving of files in the remote file system.
     * Please follow phpDoc of upload, remove and download methods to understand
     * when in use.
     *
     * @param string $prefix
     * @return $this
     */
    public function setRemotePrefix($prefix)
    {
        if (is_null($prefix)) {
            $prefix = '';
        }
        $this->remotePrefix = $prefix;

        return $this;
    }

    /**
     * Gets the prefix used for saving of files in the remote files system.
     * Please follow phpDoc of upload, remove and download methods to understand
     * when in use.
     *
     * @return string
     */
    public function getRemotePrefix()
    {
        return $this->remotePrefix;
    }

    /**
     * Opens the SSH2 and SFTP connection to the given hostname on given port.
     * Requires Credentials to be assigned before.
     *
     * @param string $host hostname
     * @param int $port port to connect on to the hostname
     *
     * @return $this
     * @throws Exception Valid credentials must be set!
     * @throws Exception Could not connect!
     * @throws Exception Could not authenticate!
     */
    public function connect($host, $port = 22)
    {
        if (!($this->getCredentials() instanceof Credentials)) {
            throw new Exception('Valid credentials must be set!');
        }

        $this->host = $host;
        $this->port = $port;

        $sshConnection = ssh2_connect($host, $port);
        if ($sshConnection === false) {
            throw new Exception("Could not connect!");
        }

        if ($this->getCredentials()->authorizeSshConnection($sshConnection) !== true) {
            throw new Exception("Could not authenticate!");
        }

        $this->setSshResource($sshConnection);
        $this->setSftpResource(ssh2_sftp($sshConnection));

        return $this;
    }

    /**
     * Closes the connection (calls 'exit') and removes the connection resources.
     *
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @return $this
     */
    public function close()
    {
        if ($this->getSshResource()) {
            $this->validateSshResource();
            ssh2_disconnect($this->getSshResource());
            $this->setSftpResource(null);
            $this->setSshResource(null);
        }

        return $this;
    }

    /**
     * Attempts to download a file using SCP protocol.
     *
     * @param string $remoteFilePath Remote file path. File must exist. [Not
     * affected by remote prefix]
     * @param string $localFileName Local file name / path. If null then script
     * will try to save in the working directory with the original basename.
     * [Affected by remote prefix]
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception File does not exist or no permissions to read!
     * @throws Exception Could not download the file!
     */
    public function scpDownload($remoteFilePath, $localFileName = null)
    {
        $this->validateSshResource();

        if (ssh2_sftp_stat($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getLocalPrefix();

        if (is_string($localFileName) === true) {
            $savePath .= $localFileName;
        } else {
            $path = pathinfo($remoteFilePath);
            $savePath .= $path['basename'];
        }

        $result = ssh2_scp_recv($this->getSshResource(), $remoteFilePath, $savePath);

        if ($result === false) {
            throw new Exception("Could not download the file!");
        }

        return $this;
    }

    /**
     * Attempts to upload a file using SCP protocol
     *
     * @param string $localFilePath [Not affected by locel prefix]
     * @param string $remoteFileName [Affected by remote prefix]
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception File does not exist or no permissions to read!
     * @throws Exception Could not upload the file!
     */
    public function scpUpload($localFilePath, $remoteFileName = null)
    {
        $this->validateSshResource();

        if (stat($localFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getRemotePrefix();

        if (is_string($remoteFileName) === true) {
            $savePath .= $remoteFileName;
        } else {
            $path = pathinfo($localFilePath);
            $savePath .= $path['basename'];
        }

        $result = ssh2_scp_send($this->getSshResource(), $localFilePath, $savePath);

        if ($result === false) {
            throw new Exception("Could not upload the file!");
        }

        return $this;
    }

    /**
     * Attempts to download a file using SFTP protocol.
     *
     * @param string $remoteFilePath Remote file path. File must exist. [Not
     * affected by remote prefix]
     * @param string $localFileName Local file name / path. If null then script
     * will try to save in the working directory with the original basename.
     * [Affected by local prefix]
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Unable to write to local file
     */
    public function download($remoteFilePath, $localFileName = null)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        $sftp_int = intval($sftp);

        $savePath = $this->getLocalPrefix();

        if (is_string($localFileName) === true) {
            $savePath .= $localFileName;
        } else {
            $path = pathinfo($remoteFilePath);
            $savePath .= $path['basename'];
        }

        if (stat("ssh2.sftp://" . $sftp_int . "/" . $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        // Remote stream
        if (!$remoteStream = @fopen("ssh2.sftp://".$sftp_int."/$remoteFilePath", 'r')) {
            throw new Exception("Unable to open remote file: $remoteFilePath");
        }

        // Local stream
        if (!$localStream = @fopen($savePath, 'w')) {
            throw new Exception("Unable to open local file for writing: $savePath");
        }

        // Write from our remote stream to our local stream
        $read = 0;
        $fileSize = filesize("ssh2.sftp://".$sftp_int."/$remoteFilePath");
        while ($read < $fileSize && ($buffer = fread($remoteStream, $fileSize - $read))) {
            // Increase our bytes read
            $read += strlen($buffer);

            // Write to our local file
            if (fwrite($localStream, $buffer) === false) {
                throw new Exception("Unable to write to local file: $savePath");
            }
        }

        // Close our streams
        fclose($localStream);
        fclose($remoteStream);

        if ($this->fileSizeVerificationEnabled && $fileSize !== filesize($savePath)) {
            throw new Exception("Different file size: " . $localFilePath);
        }

        return $this;
    }

    /**
     * Attempts to upload a file using SFTP protocol.
     *
     * @param string $localFilePath [Not affected by local prefix]
     * @param string $remoteFileName [Affected by remote prefix]
     * @return $this
     * @throws Exception Invalid connection resource! due to use of
     * validateSshResource.
     * @throws Exception File does not exist or no permissions to read!
     * @throws Exception Could not upload the file!
     */
    public function upload($localFilePath, $remoteFileName = null)
    {
        $this->validateSshResource();

        if (stat($localFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getRemotePrefix();

        if (is_string($remoteFileName) === true) {
            $savePath .= $remoteFileName;
        } else {
            $path = pathinfo($localFilePath);
            $savePath .= $path['basename'];
        }

        $sftp = $this->getSftpResource();
        $sftp_int = intval($sftp);

        // Local stream
        if (!$localStream = @fopen($localFilePath, 'r')) {
            throw new Exception("Unable to open local file for reading: $localFilePath");
        }

        // Remote stream
        if (!$remoteStream = @fopen("ssh2.sftp://".$sftp_int."/$savePath", 'w')) {
            throw new Exception("Unable to open remote file for writing: $savePath");
        }

        // Write from our remote stream to our local stream
        $read = 0;
        $fileSize = filesize($localFilePath);
        while ($read < $fileSize && ($buffer = fread($localStream, $fileSize - $read))) {
            // Increase our bytes read
            $read += strlen($buffer);

            // Write to our local file
            if (fwrite($remoteStream, $buffer) === false) {
                throw new Exception("Unable to write to local file: $savePath");
            }
        }

        // Close our streams
        fclose($localStream);
        fclose($remoteStream);

        if ($this->fileSizeVerificationEnabled && $fileSize !== filesize("ssh2.sftp://".$sftp_int."/$savePath")) {
            throw new Exception("Different file size: " . $localFilePath);
        }

        return $this;
    }

    /**
     * Attempts to remove a file using SFTP protocol.
     *
     * @param string $remoteFilePath Remote file path. File must exist. [Affected
     * by remote prefix]
     * @return $this
     * @throws Exception Invalid connection resource! due to use of
     * validateSshResource.
     * @throws Exception Unable to remove remote file!.
     */
    public function remove($remoteFilePath)
    {
        $this->validateSshResource();

        $remoteDirectory = $this->getRemotePrefix();

        if (ssh2_sftp_stat($this->getSftpResource(), $remoteDirectory . $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        if (ssh2_sftp_unlink($this->getSftpResource(), $remoteDirectory . $remoteFilePath) === false) {
            throw new Exception("Unable to remove remote file!");
        }

        return $this;
    }

    /**
     * Attempts to rename a file using SFTP protocol.
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @return $this
     * @throws Exception Invalid connection resource! due to use of
     * validateSshResource.
     * @throws Exception Unable to rename remote file!.
     */
    public function rename($remoteFilePath, $newRemoteFilePath)
    {
        $this->validateSshResource();

        $remoteDirectory = $this->getRemotePrefix();

        if (ssh2_sftp_stat($this->getSftpResource(), $remoteDirectory . $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        if (ssh2_sftp_rename($this->getSftpResource(), $remoteDirectory . $remoteFilePath, $newRemoteFilePath) === false) {
            throw new Exception("Unable to rename remote file!");
        }

        return $this;
    }

    /**
     * Gets the files list.
     *
     * @param string $remotePath Remote directory path [Not affected by remote
     * prefix]
     * @return array List of files
     * @throws Exception Invalid connection resource! due to use of
     * validateSshResource.
     * @throws Exception Folder does not exist or no permissions to read!
     * @throws Exception Unable to open remote directory!
     */
    public function getFileList($remotePath)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        $sftp_int = intval($sftp);
        if (stat("ssh2.sftp://" . $sftp_int . "/" . $remotePath) === false) {
            throw new Exception("Folder does not exist or no permissions to read!");
        }

        $handle = opendir("ssh2.sftp://".$sftp_int."/$remotePath");
        if ($handle === false) {
            throw new Exception("Unable to open remote directory!");
        }

        $files = [];

        while (false != ($entry = readdir($handle))) {
            $files[] = $entry;
        }

        closedir($handle);

        return $files;
    }

    /**
     * Gives information about a file.
     *
     * Check stat's return array format here:
     * http://php.net/manual/en/function.stat.php
     *
     * @throws Exception Invalid connection resource! due to use of
     * validateSshResource.
     * @param string $remotePath
     * @return mixed[string]
     */
    public function stat($remotePath)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        $sftp_int = intval($sftp);

        return stat("ssh2.sftp://" . $sftp_int . "/" . $remotePath);
    }

    /**
     * Creates remote directory.
     *
     * @param string $path
     * @param int $mode
     * @param boolean $recursive
     * @return $this
     */
    public function makeDirectory($path, $mode = 0777, $recursive = false)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();

        $result = ssh2_sftp_mkdir($sftp, $path, $mode, $recursive);
        if ($result === false) {
            throw new Exception("Unable to create remote directory! (" . $path . ")");
        }

        return $this;
    }

    /**
     * Removes remote directory.
     * Directory must be empty!
     *
     * @param string $path
     * @return $this
     */
    public function removeDirectory($path)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();

        $result = ssh2_sftp_rmdir($sftp, $path);
        if ($result === false) {
            throw new Exception("Unable to delete remote directory!");
        }

        return $this;
    }

    /**
     * Checks if remote file exists.
     *
     * @param string $path Remote file path. [Not affected by remote prefix]
     * @return boolean
     */
    public function fileExists($path)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        $sftp_int = intval($sftp);

        return file_exists("ssh2.sftp://" . $sftp_int . "/" . $path);
    }

    /**
     * Sets the resource created by ssh2_sftp used for all Sftp methods.
     *
     * @param resource $sftpResource
     * @return $this
     */
    protected function setSftpResource($sftpResource)
    {
        //fix for https://bugs.php.net/bug.php?id=71376
        $this->sftpResource = $sftpResource;

        return $this;
    }

    /**
     * Gets the assigned resource used by all Sftp methods.
     *
     * @return int|null
     */
    protected function getSftpResource()
    {
        return $this->sftpResource;
    }

    /**
     * Sets the resource created by ssh2_connect used for all ssh methods.
     *
     * @param resource $sshResource
     * @return $this
     */
    protected function setSshResource($sshResource)
    {
        $this->sshResource = $sshResource;

        return $this;
    }

    /**
     * Gets the assigned resource used by all ssh methods.
     *
     * @return $this
     */
    protected function getSshResource()
    {
        return $this->sshResource;
    }

    /**
     * Checks if connection resources are assigned for further use
     *
     * @return $this
     * @throws Exception Invalid connection resource!
     */
    protected function validateSshResource()
    {
        if ($this->getSshResource() === false || $this->getSshResource() === null) {
            throw new Exception("Invalid connection resource!");
        }

        return $this;
    }
}
