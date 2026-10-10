<?php

declare(strict_types=1);

namespace PivotPHP\Security\Cors;

use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable CORS configuration.
 *
 * Origins are matched exactly (`scheme://host[:port]`); `'*'` allows any
 * origin and cannot be combined with credentials.
 */
final class CorsConfig
{
    /** @var list<string> */
    public readonly array $allowedOrigins;

    /** @var list<string> */
    public readonly array $allowedMethods;

    /** @var list<string> lower-cased */
    public readonly array $allowedHeaders;

    /** @var list<string> */
    public readonly array $exposedHeaders;

    /**
     * @param list<string> $allowedOrigins exact origins, or `['*']` for any
     * @param list<string> $allowedMethods
     * @param list<string> $allowedHeaders request headers allowed in preflight
     * @param list<string> $exposedHeaders response headers readable by the browser
     * @param int|null     $maxAge         preflight cache in seconds (null omits the header)
     */
    public function __construct(
        array $allowedOrigins = [],
        array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
        array $allowedHeaders = ['Content-Type', 'Authorization'],
        array $exposedHeaders = [],
        public readonly bool $allowCredentials = false,
        public readonly ?int $maxAge = 600,
    ) {
        foreach ($allowedOrigins as $origin) {
            self::assertOrigin($origin);
        }

        if ($allowCredentials && in_array('*', $allowedOrigins, true)) {
            throw new InvalidConfigurationException(
                'CORS: "*" cannot be used as an allowed origin when credentials are allowed; '
                . 'list the origins explicitly.'
            );
        }

        if ($maxAge !== null && $maxAge < 0) {
            throw new InvalidConfigurationException('CORS: maxAge must be zero or positive.');
        }

        $this->allowedOrigins = array_values(array_unique($allowedOrigins));
        $this->allowedMethods = array_values(array_unique(array_map(
            static fn (string $method): string => self::assertToken(strtoupper($method), 'method'),
            $allowedMethods
        )));
        $this->allowedHeaders = array_values(array_unique(array_map(
            static fn (string $header): string => self::assertToken(strtolower($header), 'header'),
            $allowedHeaders
        )));
        $this->exposedHeaders = array_values(array_unique(array_map(
            static fn (string $header): string => self::assertToken($header, 'exposed header'),
            $exposedHeaders
        )));
    }

    public function allowsAnyOrigin(): bool
    {
        return in_array('*', $this->allowedOrigins, true);
    }

    public function allowsOrigin(string $origin): bool
    {
        return $this->allowsAnyOrigin() || in_array($origin, $this->allowedOrigins, true);
    }

    private static function assertOrigin(string $origin): void
    {
        if ($origin === '*') {
            return;
        }

        if ($origin === 'null') {
            throw new InvalidConfigurationException(
                'CORS: the "null" origin is sent by sandboxed documents and file:// pages and must not be allowed.'
            );
        }

        $parts = parse_url($origin);
        $isValid = is_array($parts)
            && isset($parts['scheme'], $parts['host'])
            && in_array($parts['scheme'], ['http', 'https'], true)
            && !isset($parts['path'])
            && !isset($parts['query'])
            && !isset($parts['fragment'])
            && !isset($parts['user'])
            && $origin === strtolower($origin);

        if (!$isValid) {
            throw new InvalidConfigurationException(sprintf(
                'CORS: invalid origin "%s"; expected lower-case "scheme://host[:port]" without path or trailing slash.',
                $origin
            ));
        }
    }

    private static function assertToken(string $value, string $kind): string
    {
        if (preg_match('/^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$/', $value) !== 1) {
            throw new InvalidConfigurationException(sprintf('CORS: invalid %s "%s".', $kind, $value));
        }

        return $value;
    }
}
