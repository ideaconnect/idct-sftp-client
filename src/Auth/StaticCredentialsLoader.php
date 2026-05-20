<?php

declare(strict_types=1);

namespace IDCT\Networking\Ssh\Auth;

/**
 * Returns the same {@see CredentialsInterface} instance for every
 * host. Lets callers that already construct a `Credentials` value
 * object still flow through {@see CredentialsLoaderInterface} so
 * downstream code can depend on the interface uniformly.
 */
final readonly class StaticCredentialsLoader implements CredentialsLoaderInterface
{
    /**
     * @param CredentialsInterface $credentials The single set of
     *        credentials this loader hands out, regardless of host.
     *        Typically a {@see Credentials} value object constructed
     *        via one of the named factories.
     */
    public function __construct(
        private CredentialsInterface $credentials,
    ) {}

    /**
     * Returns the wrapped credentials. The `$host` argument is
     * accepted for interface conformance and ignored.
     */
    public function load(string $host): CredentialsInterface
    {
        return $this->credentials;
    }
}
