<?php

declare(strict_types=1);

namespace PivotPHP\Security\Jwt;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable JWT authentication configuration.
 *
 * Exactly one algorithm is accepted per configuration, so a token cannot pick
 * its own algorithm. HMAC secrets must be at least as long as the hash output
 * (32 bytes for HS256); empty secrets are rejected.
 */
final class JwtConfig
{
    private const HMAC_MIN_BYTES = ['HS256' => 32, 'HS384' => 48, 'HS512' => 64];

    private const ALGORITHMS = [
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'PS256',
        'ES256', 'ES384', 'ES256K',
        'EdDSA',
    ];

    /** @var list<string> */
    public readonly array $publicPaths;

    /** @var list<string> */
    public readonly array $audience;

    /**
     * @param string|OpenSSLAsymmetricKey|OpenSSLCertificate $key verification key
     *        (secret for HS*, public key for the other algorithms)
     * @param list<string>  $publicPaths paths that skip authentication (`fnmatch` patterns, e.g. `/health`, `/docs/*`)
     * @param string|null   $cookieName  cookie read when the `Authorization` header is absent
     * @param string|null   $issuer      required `iss` claim
     * @param list<string>  $audience    accepted `aud` values (any match)
     * @param int           $leeway      clock skew tolerance in seconds for `exp`/`nbf`/`iat`
     */
    public function __construct(
        #[\SensitiveParameter]
        public readonly string|OpenSSLAsymmetricKey|OpenSSLCertificate $key,
        public readonly string $algorithm = 'HS256',
        array $publicPaths = [],
        public readonly ?string $cookieName = null,
        public readonly ?string $issuer = null,
        array $audience = [],
        public readonly int $leeway = 0,
        public readonly string $attribute = 'user',
    ) {
        if (!in_array($algorithm, self::ALGORITHMS, true)) {
            throw new InvalidConfigurationException(sprintf('JWT: unsupported algorithm "%s".', $algorithm));
        }

        if (is_string($key)) {
            if ($key === '') {
                throw new InvalidConfigurationException('JWT: the key must not be empty.');
            }

            $minBytes = self::HMAC_MIN_BYTES[$algorithm] ?? 0;
            if (strlen($key) < $minBytes) {
                throw new InvalidConfigurationException(sprintf(
                    'JWT: %s secrets must be at least %d bytes long.',
                    $algorithm,
                    $minBytes
                ));
            }
        } elseif (isset(self::HMAC_MIN_BYTES[$algorithm])) {
            throw new InvalidConfigurationException('JWT: HMAC algorithms require a string secret.');
        }

        if ($leeway < 0) {
            throw new InvalidConfigurationException('JWT: leeway must be zero or positive.');
        }

        if ($attribute === '' || $cookieName === '' || $issuer === '') {
            throw new InvalidConfigurationException('JWT: attribute, cookieName and issuer must not be empty strings.');
        }

        $this->publicPaths = array_values($publicPaths);
        $this->audience = array_values($audience);
    }

    public function isPublicPath(string $path): bool
    {
        foreach ($this->publicPaths as $pattern) {
            if (fnmatch($pattern, $path)) {
                return true;
            }
        }

        return false;
    }
}
