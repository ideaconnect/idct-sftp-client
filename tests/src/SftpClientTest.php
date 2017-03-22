<?php

namespace IDCT\Networking\Ssh\Tests;

use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Credentials;
use IDCT\Networking\Ssh\AuthMode;
use PHPUnit\Framework\TestCase;

/**
 * SftpClient tests
 *
 * @group IDCT
 * @group IDCT_Networking
 * @group IDCT_Networking_Ssh
 * @group IDCT_Networking_Ssh_SftpClient
 */
class SftpClientTest extends TestCase
{
    protected function getMocked($class, $methods = array())
    {
        return $this->getMockBuilder($class)
                      ->setMethods($methods)
                      ->getMock();
    }

    public function testSetGet()
    {
        $credentials = $this->getMocked(Credentials::class);
        $client = new SftpClient();
        $client->setCredentials($credentials);
        $this->assertEquals($credentials, $client->getCredentials());

        $client->setLocalPrefix(null);
        $this->assertEquals('', $client->getLocalPrefix());

        $client->setLocalPrefix('test');
        $this->assertEquals('test', $client->getLocalPrefix());

        $client->setRemotePrefix(null);
        $this->assertEquals('', $client->getRemotePrefix());

        $client->setRemotePrefix('test');
        $this->assertEquals('test', $client->getRemotePrefix());
    }

    public function testConnect()
    {
        //TODO
    }

    public function testClose()
    {
        //TODO
    }

    public function testScpDownload()
    {
        //TODO
    }

    public function testScpUpload()
    {
        //TODO
    }

    public function testDownload()
    {
        //TODO
    }

    public function testUpload()
    {
        //TODO
    }

    public function testRemove()
    {
        //TODO
    }

    public function testRename()
    {
        //TODO
    }

    public function testGetFileList()
    {
        //TODO
    }
}
