<?php
namespace IDCT\Networking\Ssh;

use IDCT\Networking\Ssh\Credentials;
use \Exception as Exception;

/**
 * FTP Client for PHP
 *
 * @package SftpClient
 * @version 1.0
 *
 * @copyright Bartosz Pachołek
 * @copyleft Bartosz pachołek
 * @author Bartosz Pachołek

 * @license http://opensource.org/licenses/MIT (The MIT License)
 *
 * Copyright (c) 2014, IDCT IdeaConnect Bartosz Pachołek (http://www.idct.pl/)
 * Copyleft (c) 2014, IDCT IdeaConnect Bartosz Pachołek (http://www.idct.pl/)
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
     * Credentials used for authorization of the connection
     *
     * @var Credentials
     */
    protected $credentials = null;

    /**
     * Sftp resource created by ssh2_sftp for use with all sftp methods
     *
     * @var Resource
     */
    protected $sftpResource = null;

    /**
     * Ssh connection resource created by ssh2_connect for use with all ssh methods
     * @var Resource
     */
    protected $sshResource = null;

    /**
     * Path prefix used for saving in the local file system
     *
     * @var string
     */
    protected $localPrefix = ''; //with the trailing slash

    /**
     * Path prefix used for saving in the remote file system
     * @var string
     */
    protected $remotePrefix = ''; //with the trailing slash

    /**
     * If enabled verifies each file for same file size.
     * @var boolean
     */
    protected $fileSizeVerificationEnabled = false;

    /**
     * Host
     * @var string
     */
    protected $host;

    /**
     * Port
     * @var int
     */
    protected $port;

    /**
     * Constructor
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
     * Setter for the credentials used for authorization
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
     * Getter of assigned authorization credentials object
     *
     * @return Credentials|null
     */
    public function getCredentials()
    {
        return $this->credentials;
    }

    /**
     * Sets the prefix used for saving of files in the local file system
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
     * Gets the prefix used for saving of files in the local file system
     *
     * @return string
     */
    public function getLocalPrefix()
    {
        return $this->localPrefix;
    }

    /**
     * Sets the prefix used for saving of files in the remote file system
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
     * Gets the prefix used for saving of files in the remote files system
     *
     * @return string
     */
    public function getRemotePrefix()
    {
        return $this->remotePrefix;
    }

    /**
     * Sets the resource created by ssh2_sftp used for all Sftp methods
     *
     * @param resource $sftpResource
     * @return $this
     */
    protected function setSftpResource($sftpResource)
    {
        //fix for https://bugs.php.net/bug.php?id=71376
        $this->sftpResource = intval($sftpResource);

        return $this;
    }

    /**
     * Gets the assigned resource used by all Sftp methods
     *
     * @return int|null
     */
    protected function getSftpResource()
    {
        return $this->sftpResource;
    }

    /**
     * Sets the resource created by ssh2_connect used for all ssh methods
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
     * Gets the assigned resource used by all ssh methods
     *
     * @return $this
     */
    protected function getSshResource()
    {
        return $this->sshResource;
    }

    /**
     * Opens the SSH2 and SFTP connection to the given hostname on given port. Requires Credentials to be assigned before.
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

    /**
     * Closes the connection (calls 'exit') and removes the connection resources.
     *
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @return $this
     */
    public function close()
    {
        $this->validateSshResource();
        @ssh2_exec($this->getSshResource(), 'exit');
        $this->setSftpResource(null);
        $this->setSshResource(null);

        return $this;
    }

    /**
     * Attempts to download a file using SCP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @param string $localFileName Local file name / path. If null then script will try to save in the working directory with the original basename.
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
     * @param string $localFilePath
     * @param string $remoteFileName
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
     * Attempts to download a file using SFTP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @param string $localFileName Local file name / path. If null then script will try to save in the working directory with the original basename.
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Unable to write to local file
     */
    public function download($remoteFilePath, $localFileName = null)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        if (stat("ssh2.sftp://" . $sftp . "/" . $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getLocalPrefix();

        if (is_string($localFileName) === true) {
            $savePath .= $localFileName;
        } else {
            $path = pathinfo($remoteFilePath);
            $savePath .= $path['basename'];
        }


        // Remote stream
        if (!$remoteStream = @fopen("ssh2.sftp://".($sftp)."/$remoteFilePath", 'r')) {
            throw new Exception("Unable to open remote file: $remoteFilePath");
        }

        // Local stream
        if (!$localStream = @fopen($savePath, 'w')) {
            throw new Exception("Unable to open local file for writing: $savePath");
        }

        // Write from our remote stream to our local stream
        $read = 0;
        $fileSize = filesize("ssh2.sftp://".($sftp)."/$remoteFilePath");
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
     * Attempts to upload a file using SFTP protocol
     *
     * @param string $localFilePath
     * @param string $remoteFileName
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
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

        // Local stream
        if (!$localStream = @fopen($localFilePath, 'r')) {
                throw new Exception("Unable to open local file for reading: $localFilePath");
        }

        // Remote stream
        if (!$remoteStream = @fopen("ssh2.sftp://".$sftp."/$savePath", 'w')) {
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

        if ($this->fileSizeVerificationEnabled && $fileSize !== filesize("ssh2.sftp://".$sftp."/$savePath")) {
            throw new Exception("Different file size: " . $localFilePath);
        }

        return $this;
    }

    /**
     * Attempts to remove a file using SFTP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception Unable to remove remote file!.
     */
    public function remove($remoteFilePath)
    {
        $this->validateSshResource();

        if (ssh2_sftp_stat($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        if (ssh2_sftp_unlink($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("Unable to remove remote file!");
        }

        return $this;
    }

    /**
     * Attempts to rename a file using SFTP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @return $this
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception Unable to rename remote file!.
     */
    public function rename($remoteFilePath, $newRemoteFilePath)
    {
        $this->validateSshResource();

        if (ssh2_sftp_stat($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        if (ssh2_sftp_rename($this->getSftpResource(), $remoteFilePath, $newRemoteFilePath) === false) {
            throw new Exception("Unable to rename remote file!");
        }

        return $this;
    }

    /**
     * Gets the files list
     *
     * @param string $remotePath Remote directory path
     * @return array List of files
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception Folder does not exist or no permissions to read!
     * @throws Exception Unable to open remote directory!
     */
    public function getFileList($remotePath)
    {
        $this->validateSshResource();
        $sftp = $this->getSftpResource();
        if (stat("ssh2.sftp://" . $sftp . "/" . $remotePath) === false) {
            throw new Exception("Folder does not exist or no permissions to read!");
        }

        $handle = opendir("ssh2.sftp://".$sftp."/$remotePath");
        if ($handle === false) {
            throw new Exception("Unable to open remote directory!");
        }

        $files = array();

        while (false != ($entry = readdir($handle))) {
            $files[] = $entry;
        }

        return $files;
    }
}
