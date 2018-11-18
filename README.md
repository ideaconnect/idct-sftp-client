idct-sftp-client
==================

Library that provides wrapper methods around SSH2, SCP and SFTP to simplify file
download/upload over SSH/SCP/SFTP.

warning
=======
I am still thinking about unification of download / upload methods by passing a
parameter which would define the connection type therefore method names may change.

installation
============

Depending on your project include the files directly or use autoloader.

### Direct usage

Just include all the required files:

```php
include "/path/to/idct/sftp-client/src/AuthMode.php";
include "/path/to/idct/sftp-client/src/Credentials.php";
include "/path/to/idct/sftp-client/src/SftpClient.php";
```

### Composer

Just execute:

```php
composer require idct/sftp-client
```

which will create `vendor` folder with `idct/sftp-client`. Then just include the
autoloader:

```php
include "vendor/autoload.php";
```

usage
=====

After you have installed the project import required classes in your project:

```php
use IDCT\Networking\Ssh\SftpClient;
use IDCT\Networking\Ssh\Credentials;
```

Initialize instance of the class:

```php
$client = new SftpClient();
```

Create authorization mode to your SFTP server:

### When you have username and password:

```php
$credentials = Credentials::withPassword($username, $password);
$client->setCredentials($credentials);
```

### When you have public key:

```php
$credentials = Credentials::withPublicKey($username, $publicKey, $privateKey, $passphrase = null);
$client->setCredentials($credentials);
```

`$publicKey` and `$privateKey` are paths to respective files.

### Connect to the server

```php
$client->connect($host);
```


### Downloading using SFTP:

```php
$client->download(ENTER_REMOTE_FILE_NAME);
$client->download(ENTER_REMOTE_FILE_NAME, ENTER_LOCAL_FILE_NAME);
```

### Uploading using SFTP:

```php
$client->upload(ENTER_LOCAL_FILE_NAME);
$client->upload(ENTER_LOCAL_FILE_NAME, ENTER_REMOTE_FILE_NAME);
```

### Downloading using SCP:
```php
$client->scpDownload(ENTER_REMOTE_FILE_NAME);
```

### Uploading using SCP:
```php
$client->scpUpload(ENTER_LOCAL_FILE_NAME,ENTER_REMOTE_FILE_NAME);
```

### Closing connection:

```php
$client->close();
```

### Remote prefix, local prefix

Prefixes set using methods: `setRemotePrefix` and `setLocalPrefix` allow to set
common directories for storage. Please follow phpDoc of respective upload/download
methods to know when

contribution
============

If you find any issues or want to add new features please use the Issues or Pull
Request functions: code addition is much appreciated!

Before sending code be sure to run fix_code.sh to clean it up.

Thanks!
