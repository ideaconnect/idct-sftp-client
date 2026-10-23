<?php

declare(strict_types=1);

use Behat\Config\Config;
use Behat\Config\Formatter\PrettyFormatter;
use Behat\Config\Profile;
use Behat\Config\Suite;
use IDCT\Networking\Ssh\Tests\Functional\SftpContext;

// Behat 4 reads only PHP configuration (behat.yml is no longer supported).
return (new Config())
    ->withProfile((new Profile('default', [
        'autoload' => [
            '' => '%paths.base%/tests/functional/bootstrap',
        ],
    ]))
        ->withFormatter(new PrettyFormatter())
        ->withSuite((new Suite('default'))
            ->withContexts(SftpContext::class)
            ->withPaths('%paths.base%/tests/functional/features')));
