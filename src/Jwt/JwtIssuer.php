<?php

declare(strict_types=1);

namespace PivotPHP\Security\Jwt;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Exception\MissingDependencyException;

/**
 * Issues JWTs that `JwtAuthMiddleware` accepts (adapter for `firebase/php-jwt`).
 *
 * Shares the `JwtConfig` used for verification, so the algorithm, `iss` and
 * `aud` always match. HMAC algorithms sign with the configured secret;
 * asymmetric algorithms need the private key.
 *
 * ```php
 * $issuer = new JwtIssuer($config);
 * $token = $issuer->issue(['sub' => $user->id, 'role' => 'admin'], ttl: 3600);
 * ```
 */
final class JwtIssuer
{
    private const RESERVED = ['iat', 'nbf', 'exp', 'iss', 'aud'];

    /**
     * @param string|OpenSSLAsymmetricKey|null $privateKey signing key for RS*, PS256, ES* and EdDSA (ignored for HS*)
     */
    public function __construct(
        private readonly JwtConfig $config,
        #[\SensitiveParameter]
        private readonly string|OpenSSLAsymmetricKey|null $privateKey = null,
    ) {
        if (!class_exists(JWT::class)) {
            throw MissingDependencyException::forPackage(self::class, 'firebase/php-jwt');
        }

        if (!$this->isHmac() && ($privateKey === null || $privateKey === '')) {
            throw new InvalidConfigurationException(sprintf(
                'JWT: %s tokens need the private key to be issued.',
                $config->algorithm
            ));
        }
    }

    /**
     * Issues a signed token.
     *
     * `iat`, `nbf`, `exp`, `iss` and `aud` are set from the clock and the
     * configuration; passing them in `$claims` is rejected.
     *
     * @param array<string, mixed> $claims application claims (e.g. `sub`, roles)
     * @param int                  $ttl    lifetime in seconds
     */
    public function issue(array $claims, int $ttl = 3600, ?int $now = null): string
    {
        if ($ttl <= 0) {
            throw new InvalidConfigurationException('JWT: ttl must be positive.');
        }

        $reserved = array_intersect(array_keys($claims), self::RESERVED);
        if ($reserved !== []) {
            throw new InvalidConfigurationException(sprintf(
                'JWT: the claims %s are set by the issuer and cannot be passed.',
                implode(', ', $reserved)
            ));
        }

        $now ??= time();
        $payload = $claims + ['iat' => $now, 'nbf' => $now, 'exp' => $now + $ttl];

        if ($this->config->issuer !== null) {
            $payload['iss'] = $this->config->issuer;
        }

        if ($this->config->audience !== []) {
            $payload['aud'] = count($this->config->audience) === 1
                ? $this->config->audience[0]
                : $this->config->audience;
        }

        return JWT::encode($payload, $this->signingKey(), $this->config->algorithm);
    }

    private function isHmac(): bool
    {
        return str_starts_with($this->config->algorithm, 'HS');
    }

    private function signingKey(): string|OpenSSLAsymmetricKey|OpenSSLCertificate
    {
        if ($this->isHmac() || $this->privateKey === null) {
            return $this->config->key;
        }

        return $this->privateKey;
    }
}
