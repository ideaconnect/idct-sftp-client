<?php

namespace IDCT\Networking\Ssh;

use Exception as Exception;

/**
 * SshCredentials for SftpClient
 *
 * @package SFTPClient
 * @version 0.3.1
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
class Credentials
{
    /**
     * Username for authorization to the server
     * @var string
     */
    protected $username;

    /**
     * Authorization password used in case of AuthMode::PUBLIC_KEY mode
     *
     * @var string
     */
    protected $password;

    /**
     * Server authorization mode
     *
     * @var \IDCt\Networking\Ssh\AuthMode
     */
    protected $mode;

    /**
     * Public key file path - used in case of AuthMode::PUBLIC_KEY mode
     *
     * @var string
     */
    protected $publicKey;

    /**
     * Private key file path - used in case of AuthMode::PUBLIC_KEY mode
     * @var string
     */
    protected $privateKey;

    /**
     * Private key passphrase (if needed) - used in case of AuthMode::PUBLIC_KEY mode
     * @var string
     */
    protected $privateKeyPassphrase;

    /**
     * Constructor. Should not be really used. Check the static methods
     *
     * @return self
     */
    public function __construct()
    {
        return $this;
    }

    /**
     * Creates a new Credentials object with the AuthMode::PASSWORD authorization mode. Requires username and password.
     *
     * @param string $username Authorization username
     * @param string $password Authorization password
     * @return Credentials
     */
    public static function withPassword($username, $password)
    {
        $instance = new self();
        $instance->setMode(AuthMode::PASSWORD);
        $instance->setUsername($username);
        $instance->setPassword($password);

        return $instance;
    }

    /**
     * Creates a new Credentials object with the AuthMode::PUBLIC_KEY authorizationmdoe. Requires username and keys details.
     * @param string $username Authorization username
     * @param string $publicKey Public key path
     * @param string $privateKey Private key path
     * @param string $passphrase Passphrase for Private key (if required)
     * @return Credentials
     */
    public static function withPublicKey($username, $publicKey, $privateKey, $passphrase = null)
    {
        $instance = new self();
        $instance->setMode(AuthMode::PUBLIC_KEY);
        $instance->setUsername($username);
        $instance->setPublicKey($publicKey);
        $instance->setPrivateKey($privateKey, $passphrase);

        return $instance;
    }

    public static function withBoth($username, $password, $publicKey, $privateKey, $passphrase = null)
    {
        $instance = new self();
        $instance->setMode(AuthMode::BOTH);
        $instance->setUsername($username);
        $instance->setPassword($password);
        $instance->setPublicKey($publicKey);
        $instance->setPrivateKey($privateKey, $passphrase);

        return $instance;
    }

    /**
     * Attempts to authorize the given ssh2 connection resource
     *
     * @param resource $connectionResource Ssh2_connect connection resource
     * @return boolean True on success
     * @throws Exception Username not set!
     * @throws Exception Mode not set!
     * @throws Exception Password required for PASSWORD mode!
     * @throws Exception Public Key required for PUBLIC KEY mode!
     * @throws Exception Private Key required for PUBLIC KEY mode!
     */
    public function authorizeSshConnection($connectionResource)
    {
        if ($connectionResource === null || $connectionResource === false) {
            throw new Exception("Connected Ssh resource is required!");
        }

        $this->validate();

        //passed the validation so we can really authorize the connection
        switch ($this->mode) {
            case (AuthMode::NONE):
                $authResult = ssh2_auth_none($connectionResource, $this->username);
                if ($authResult !== true) {
                    //we ignore here the fact of returning possible auth options: we want to authorize using this method. Full stop.
                    return false;
                } else {
                    return true;
                }
                // no break
            case (AuthMode::PASSWORD):
                return ssh2_auth_password($connectionResource, $this->username, $this->password);
            case (AuthMode::PUBLIC_KEY):
                return ssh2_auth_pubkey_file($connectionResource, $this->username, $this->publicKey, $this->privateKey, $this->privateKeyPassphrase);
            case (AuthMode::BOTH):
                @ssh2_auth_pubkey_file($connectionResource, $this->username, $this->publicKey, $this->privateKey, $this->privateKeyPassphrase);

                return ssh2_auth_password($connectionResource, $this->username, $this->password);
        }
    }

    /**
     * Sets the authorization mdoe
     *
     * @param int $mode Use AuthMode constants
     * @todo use Enum
     */
    public function setMode($mode)
    {
        $this->mode = $mode;
    }

    /**
     * Gets the assigned authorization mode
     * @return int|null Use AuthMode constants
     * @todo use Enum
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * Sets the authorization username
     *
     * @param string $username
     * @return self
     * @throws Exception Username must be at least 1 character long!
     */
    public function setUsername($username)
    {
        if (strlen($username) < 1) {
            throw new Exception("Username must be at least 1 character long!");
        }
        $this->username = $username;

        return $this;
    }

    /**
     * Gets the set authorization username
     *
     * @return string|null
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Sets the authorization password for the AuthMode::PASSWORD mode
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        //technically it can be an empty string
        $this->password = $password;

        return $this;
    }

    /**
     * Gets the assigned password
     * @return string|null
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Sets the public key file path to be used with AuthMode::PUBLIC_KEY mode
     *
     * @param string $path
     * @return self
     * @throws Exception Public Key file does not exist!
     */
    public function setPublicKey($path)
    {
        if (! file_exists($path)) {
            throw new Exception("Public Key file does not exist!");
        }
        $this->publicKey = $path;

        return $this;
    }

    /**
     * Gets the public key file path
     *
     * @return string|null
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * Sets the private key file path and (if required) passphrase to be used with AuthMode::PUBLIC_KEY mode
     *
     * @param string $path
     * @param string $passphrase (only if requried)
     * @return self
     * @throws Exception PrivateKey file does not exist!
     */
    public function setPrivateKey($path, $passphrase = null)
    {
        if (! file_exists($path)) {
            throw new Exception("Private Key file does not exist");
        }
        $this->privateKey = $path;
        $this->privateKeyPassphrase = $passphrase;

        return $this;
    }

    /**
     * Gets the private key file path
     *
     * @return string|null
     */
    public function getPrivateKeyPath()
    {
        return $this->privateKey;
    }

    /**
     * Gets the private key passphrase
     *
     * @return string|null
     */
    public function getPrivateKeyPassphrase()
    {
        return $this->privateKeyPassphrase;
    }

    /**
     * Checks if attributes required by current AuthMode ($mode) are set.
     *
     * @return boolean Returns true on success.
     * @throws Exception Password required for PASSWORD mode!
     * @throws Exception Public Key required for PUBLIC KEY mode!
     * @throws Exception Private Key required for PUBLIC KEY mode!
     */
    protected function validateAgainstMode()
    {
        if ($this->needPassword() &&
            $this->password === null
        ) {
            throw new Exception("Password required for PASSWORD mode!");
        }

        if ($this->needKeys()) {
            if ($this->publicKey === null) {
                throw new Exception("Public Key required for BOTH mode!");
            }

            if ($this->privateKey === null) {
                throw new Exception("Private Key required for BOTH mode!");
            }
        }

        return true;
    }

    protected function needPassword()
    {
        return $this->mode == AuthMode::PASSWORD || $this->mode == AuthMode::BOTH;
    }

    protected function needKeys()
    {
        return $this->mode == AuthMode::PUBLIC_KEY || $this->mode == AuthMode::BOTH;
    }

    /**
     * Checks if everything is set for authorization
     *
     * @return boolean Returns true on success
     * @throws Exception Username not set!
     * @throws Exception Mode not set!
     * @throws Exception Password required for PASSWORD mode!
     * @throws Exception Public Key required for PUBLIC KEY mode!
     * @throws Exception Private Key required for PUBLIC KEY mode!
     */
    protected function validate()
    {
        if ($this->username === null) {
            throw new Exception("Username not set!");
        }

        if (is_int($this->mode) === false) {
            throw new Exception("Mode not set!");
        }

        $this->validateAgainstMode();

        return true;
    }
}
