<?php

declare(strict_types=1);

namespace PivotPHP\Security\Proxy;

use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable trusted-proxy configuration.
 *
 * Only requests whose `REMOTE_ADDR` is one of the trusted proxies may set the
 * client IP through the forwarding header.
 */
final class TrustedProxyConfig
{
    /** @var list<string> */
    public readonly array $trustedProxies;

    /**
     * @param list<string> $trustedProxies IPv4/IPv6 addresses or CIDR ranges (e.g. `10.0.0.0/8`)
     * @param string       $header         forwarding header holding a comma-separated IP chain
     * @param string       $attribute      request attribute that receives the client IP
     */
    public function __construct(
        array $trustedProxies = [],
        public readonly string $header = 'X-Forwarded-For',
        public readonly string $attribute = 'client_ip',
    ) {
        foreach ($trustedProxies as $proxy) {
            if (!IpRange::isValid($proxy)) {
                throw new InvalidConfigurationException(sprintf(
                    'Trusted proxy "%s" is not a valid IP address or CIDR range.',
                    $proxy
                ));
            }
        }

        if ($header === '' || $attribute === '') {
            throw new InvalidConfigurationException('Trusted proxy header and attribute must not be empty.');
        }

        $this->trustedProxies = array_values($trustedProxies);
    }

    public function isTrusted(string $ip): bool
    {
        foreach ($this->trustedProxies as $proxy) {
            if (IpRange::contains($proxy, $ip)) {
                return true;
            }
        }

        return false;
    }
}
