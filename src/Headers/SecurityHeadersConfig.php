<?php

declare(strict_types=1);

namespace PivotPHP\Security\Headers;

use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable security-headers configuration.
 *
 * Defaults target a JSON API (OWASP REST Security cheat sheet):
 * HSTS, `nosniff`, `X-Frame-Options: DENY`, a restrictive
 * `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and
 * `Referrer-Policy: strict-origin-when-cross-origin`.
 *
 * Header values are produced by `bepsvpt/secure-headers`. `$overrides` is
 * merged last into that library's configuration array for options not
 * modelled here (Permissions-Policy, COOP/COEP/CORP, reporting...).
 */
final class SecurityHeadersConfig
{
    /** @var array<string, mixed> */
    public readonly array $contentSecurityPolicy;

    /** @var array<string, mixed> */
    public readonly array $overrides;

    /**
     * @param array<string, mixed>|null $contentSecurityPolicy CSP in bepsvpt/secure-headers format
     *        (e.g. `['default-src' => ['self' => true]]`); `null` disables the header
     * @param array<string, mixed>      $overrides raw bepsvpt/secure-headers configuration
     */
    public function __construct(
        public readonly bool $hsts = true,
        public readonly int $hstsMaxAge = 31536000,
        public readonly bool $hstsIncludeSubDomains = true,
        public readonly bool $hstsPreload = false,
        public readonly string $frameOptions = 'deny',
        public readonly string $referrerPolicy = 'strict-origin-when-cross-origin',
        ?array $contentSecurityPolicy = [
            'default-src' => ['none' => true],
            'frame-ancestors' => ['none' => true],
        ],
        array $overrides = [],
    ) {
        if ($hstsMaxAge < 0) {
            throw new InvalidConfigurationException('Security headers: hstsMaxAge must be zero or positive.');
        }

        if ($hstsPreload && (!$hstsIncludeSubDomains || $hstsMaxAge < 31536000)) {
            throw new InvalidConfigurationException(
                'Security headers: HSTS preload requires includeSubDomains and a max-age of at least 31536000.'
            );
        }

        if (!in_array(strtolower($frameOptions), ['deny', 'sameorigin'], true)) {
            throw new InvalidConfigurationException('Security headers: frameOptions must be "deny" or "sameorigin".');
        }

        $policies = [
            'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
            'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
        ];
        if (!in_array($referrerPolicy, $policies, true)) {
            throw new InvalidConfigurationException(sprintf(
                'Security headers: invalid referrerPolicy "%s".',
                $referrerPolicy
            ));
        }

        $this->contentSecurityPolicy = $contentSecurityPolicy === null
            ? ['enable' => false]
            : ['enable' => true] + $contentSecurityPolicy;
        $this->overrides = $overrides;
    }

    /**
     * Configuration array consumed by `bepsvpt/secure-headers`.
     *
     * @return array<string, mixed>
     */
    public function toLibraryConfig(): array
    {
        return [
            'x-content-type-options' => 'nosniff',
            'x-frame-options' => strtoupper($this->frameOptions),
            'x-xss-protection' => '',
            'x-download-options' => '',
            'x-permitted-cross-domain-policies' => 'none',
            'referrer-policy' => $this->referrerPolicy,
            'cross-origin-embedder-policy' => '',
            'cross-origin-opener-policy' => '',
            'cross-origin-resource-policy' => '',
            'permissions-policy' => ['enable' => false],
            'hsts' => [
                'enable' => $this->hsts,
                'max-age' => $this->hstsMaxAge,
                'include-sub-domains' => $this->hstsIncludeSubDomains,
                'preload' => $this->hstsPreload,
            ],
            'csp' => $this->contentSecurityPolicy,
        ];
    }
}
