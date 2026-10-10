# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
