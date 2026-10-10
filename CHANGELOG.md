# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-10

First stable release: the public API (middlewares, configuration objects and exceptions) follows
Semantic Versioning from now on. Adopted by `pivotphp/core` 4.0.0, which removed its own security
middlewares in favour of this package.

### Added

- **`Jwt\JwtIssuer`** — issues tokens accepted by `JwtAuthMiddleware` from the same `JwtConfig`:
  `issue(array $claims, int $ttl = 3600)` sets `iat`/`nbf`/`exp` and `iss`/`aud`; reserved claims cannot
  be overridden; asymmetric algorithms require the private key.

### Changed

- Optional adapter libraries are constrained to their tested major versions via `conflict`
  (`bepsvpt/secure-headers` 9.x, `firebase/php-jwt` 7.x from 7.1.1, `symfony/rate-limiter` 6.4–8.x,
  `yiisoft/csrf` 2.x from 2.2). Required dependencies remain only the PSR-7/15/17 interfaces.
- Development tools raised past published advisories (`phpunit/phpunit` ^10.5.62|^11.5.50,
  `squizlabs/php_codesniffer` ^3.13.6).

### Tests

- Scenarios ported from `pivotphp-core` (CORS and security headers), with expectations corrected where
  the core asserted wrong behaviour (`Access-Control-Allow-Origin: null`, `*` on non-CORS requests,
  preflight reaching the handler, `X-XSS-Protection`).

## [0.1.0] - 2026-10-10

### Added

- **`Cors\CorsMiddleware`** / `CorsConfig` — Fetch-standard CORS: preflight answered without reaching
  the handler (`204`, or `403` for disallowed origin/method/header), exact origin matching,
  `Vary: Origin`, credentials only with explicit origins.
- **`Proxy\TrustedProxyMiddleware`** / `TrustedProxyConfig` — resolves the client IP into the
  `client_ip` attribute, honouring `X-Forwarded-For` only from trusted proxies (IPv4/IPv6 CIDR).
- **`Headers\SecurityHeadersMiddleware`** / `SecurityHeadersConfig` — adapter for
  `bepsvpt/secure-headers` with JSON-API defaults (HSTS, `nosniff`, `DENY`, restrictive CSP,
  `strict-origin-when-cross-origin`).
- **`Csrf\CsrfMiddleware`** / `CsrfConfig` — adapter for `yiisoft/csrf`; protects every
  state-changing method, accepts the token from the body or header.
- **`Jwt\JwtAuthMiddleware`** / `JwtConfig` — adapter for `firebase/php-jwt`; single algorithm,
  minimum secret length, `iss`/`aud` checks, public paths, claims in the `user` attribute.
- **`RateLimit\RateLimitMiddleware`** / `RateLimitConfig` — adapter for `symfony/rate-limiter`;
  `429` with `Retry-After` and `X-RateLimit-*` headers, keyed by the resolved client IP.
- `Exception\InvalidConfigurationException` and `Exception\MissingDependencyException`, both
  implementing `Exception\SecurityException`.

[1.0.0]: https://github.com/PivotPHP/pivotphp-security/releases/tag/v1.0.0
[0.1.0]: https://github.com/PivotPHP/pivotphp-security/releases/tag/v0.1.0
