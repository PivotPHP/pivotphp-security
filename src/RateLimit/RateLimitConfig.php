<?php

declare(strict_types=1);

namespace PivotPHP\Security\RateLimit;

use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable rate-limit configuration.
 *
 * The limit, window and policy live in the `symfony/rate-limiter` factory;
 * this object only controls how the client key is resolved and which headers
 * are exposed.
 */
final class RateLimitConfig
{
    /**
     * @param string $keyPrefix         prefix for limiter keys (use one per route group, e.g. `login:`)
     * @param string $clientIpAttribute attribute set by `TrustedProxyMiddleware`; falls back to `REMOTE_ADDR`
     * @param bool   $exposeHeaders     add `X-RateLimit-Limit`/`X-RateLimit-Remaining` to accepted responses
     */
    public function __construct(
        public readonly string $keyPrefix = '',
        public readonly string $clientIpAttribute = 'client_ip',
        public readonly bool $exposeHeaders = true,
    ) {
        if ($clientIpAttribute === '') {
            throw new InvalidConfigurationException('Rate limit: clientIpAttribute must not be empty.');
        }
    }
}
