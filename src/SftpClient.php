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
     * @var \IDCT\Networking\Ssh\Credentials
     */
    protected $credentials = null;

    /**
     * Sftp resource created by ssh2_sftp for use with all sftp methods
     *
     * @var resource
     */
    protected $sftpResource = null;

    /**
     * Ssh connection resource created by ssh2_connect for use with all ssh methods
     * @var resource
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
     * Constructor
     *
     * Checks if ssh2 extension is loaded.
     */
    public function __construct()
    {
        if ( !extension_loaded('ssh2') ) {
            throw new Exception('Ssh2 extension is not loaded!');
        }

        return $this;
    }

    /**
     * Setter for the credentials used for authorization
     *
     * @param \IDCT\Networking\Ssh\Credentials $credentials Credentials object used for authorization
     * @return self
     */
    public function setCredentials(Credentials $credentials)
    {
        $this->credentials = $credentials;

        return $this;
    }

    /**
     * Getter of assigned authorization credentials object
     *
     * @return \IDCT\Networking\Ssh\Credentials|null
     */
    public function getCredentials() {
        return $this->credentials;
    }

    /**
     * Sets the prefix used for saving of files in the local file system
     *
     * @param string $prefix Prefix used for saving of files in the local file system
     * @return self
     */
    public function setLocalPrefix($prefix)
    {
        if(is_null($prefix)) {
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
     * @return \IDCT\Networking\Ssh\SftpClient
     */
    public function setRemotePrefix($prefix)
    {
        if(is_null($prefix)) $prefix = '';
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
     * @return self
     */
    protected function setSftpResource($sftpResource)
    {
        $this->sftpResource = $sftpResource;

        return $this;
    }

    /**
     * Gets the assigned resource used by all Sftp methods
     *
     * @return sftpResource|null
     */
    protected function getSftpResource()
    {
        return $this->sftpResource;
    }

    /**
     * Sets the resource created by ssh2_connect used for all ssh methods
     *
     * @param resource $sshResource
     * @return self
     */
    protected function setSshResource($sshResource)
    {
        $this->sshResource = $sshResource;

        return $this;
    }

    /**
     * Gets the assigned resource used by all ssh methods
     *
     * @return self
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
     * @return self
     * @throws Exception Valid credentials must be set!
     * @throws Exception Could not connect!
     * @throws Exception Could not authenticate!
     */
    public function connect($host, $port = 22)
    {
        if(!($this->getCredentials() instanceof Credentials))
        {
            throw new Exception('Valid credentials must be set!');
        }

        $sshConnection = ssh2_connect($host, $port);
        if($sshConnection === false) {
            throw new Exception("Could not connect!");
        }

        if($this->getCredentials()->authorizeSshConnection($sshConnection) !== true) {
            throw new Exception("Could not authenticate!");
        }

        $this->setSshResource($sshConnection);
        $this->setSftpResource(ssh2_sftp($sshConnection));

        return $this;
    }

    /**
     * Checks if connection resources are assigned for further use
     *
     * @return self
     * @throws Exception Invalid connection resource!
     */
    protected function validateSshResource()
    {
        if($this->getSshResource() === false || $this->getSshResource() === null) {
            throw new Exception("Invalid connection resource!");
        }

        return $this;
    }

    /**
     * Closes the connection (calls 'exit') and removes the connection resources.
     *
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @return self
     */
    public function close()
    {
        $this->validateSshResource();
        ssh2_exec($this->getSshResource(), 'exit');
        $this->setSftpResource(null);
        $this->setSshResource(null);

        return $this;
    }

    /**
     * Attempts to download a file using SCP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @param string $localFileName Local file name / path. If null then script will try to save in the working directory with the original basename.
     * @return self
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception File does not exist or no permissions to read!
     * @throws Exception Could not download the file!
     */
    public function scpDownload($remoteFilePath, $localFileName = null)
    {
        $this->validateSshResource();

        if(ssh2_sftp_stat($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getLocalPrefix();

        if(is_string($localFileName) === true) {
            $savePath .= $localFileName;
        } else {
            $path = pathinfo($remoteFilePath);
            $savePath .= $path['basename'];
        }

        $result = ssh2_scp_recv($this->getSshResource(), $remoteFilePath, $savePath);

        if($result === false) {
            throw new Exception("Could not download the file!");
        }

        return $this;
    }

    /**
     * Attempts to upload a file using SCP protocol
     *
     * @param string $localFilePath
     * @param string $remoteFileName
     * @return self
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Exception File does not exist or no permissions to read!
     * @throws Exception Could not upload the file!
     */
    public function scpUpload($localFilePath, $remoteFileName = null)
    {
        $this->validateSshResource();

        if(stat($localFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getRemotePrefix();

        if(is_string($remoteFileName) === true) {
            $savePath .= $remoteFileName;
        } else {
            $path = pathinfo($localFilePath);
            $savePath .= $path['basename'];
        }

        $result = ssh2_scp_send($this->getSshResource(), $localFilePath, $remoteFileName);

        if($result === false) {
            throw new Exception("Could not upload the file!");
        }

        return $this;
    }

    /**
     * Attempts to download a file using SFTP protocol
     *
     * @param string $remoteFilePath Remote file path. File must exist.
     * @param string $localFileName Local file name / path. If null then script will try to save in the working directory with the original basename.
     * @return self
     * @throws Exception Invalid connection resource! due to use of validateSshResource.
     * @throws Unable to write to local file
     */
    public function download($remoteFilePath, $localFileName = null)
    {
        $this->validateSshResource();

        if(ssh2_sftp_stat($this->getSftpResource(), $remoteFilePath) === false) {
            throw new Exception("File does not exist or no permissions to read!");
        }

        $savePath = $this->getLocalPrefix();

        if(is_string($localFileName) === true) {
            $savePath .= $localFileName;
        } else {
            $path = pathinfo($remoteFilePath);
            $savePath .= $path['basename'];
        }

        // Remote stream
        if (!$remoteStream = @fopen("ssh2.sftp://$sftp/$remoteFilePath", 'r')) {
            throw new Exception("Unable to open remote file: $remoteFilePath");
        }

        // Local stream
        if (!$localStream = @fopen($savePath, 'w')) {
            throw new Exception("Unable to open local file for writing: $savePath");
        }

        // Write from our remote stream to our local stream
        $read = 0;
        $fileSize = filesize("ssh2.sftp://$sftp/$remoteFilePath");
        while ($read < $fileSize && ($buffer = fread($remoteStream, $fileSize - $read))) {
            // Increase our bytes read
            $read += strlen($buffer);

            // Write to our local file
            if (fwrite($localStream, $buffer) === FALSE) {
                throw new Exception("Unable to write to local file: $savePath");
            }
        }

        // Close our streams
        fclose($localStream);
        fclose($remoteStream);

        return $this;
    }
}
