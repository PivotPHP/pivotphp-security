# PivotPHP Security

[![PHP Version](https://img.shields.io/badge/php-%5E8.1-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PSR-15](https://img.shields.io/badge/PSR--15-middleware-brightgreen)](https://www.php-fig.org/psr/psr-15/)

Security middlewares for [PivotPHP](https://github.com/PivotPHP) and **any PSR-15 pipeline**.

- One middleware per concern: CORS, trusted proxies, security headers, CSRF, JWT, rate limiting.
- **Fail closed**: a failed check returns `401`/`403`/`429` and never reaches your handler.
- **Validated configuration**: unsafe settings (`*` origin with credentials, empty JWT secret,
  `POST` declared "safe"...) throw `InvalidConfigurationException` when the config is built.
- **No hand-rolled crypto**: JWT, CSRF tokens, header building and rate limiting delegate to
  established libraries; this package provides the PSR-15 adapters.

The only required dependencies are the PSR interfaces. Each adapter needs its library, installed on
demand:

| Middleware | Library | Install |
|---|---|---|
| `Cors\CorsMiddleware` | — | — |
| `Proxy\TrustedProxyMiddleware` | — | — |
| `Headers\SecurityHeadersMiddleware` | [bepsvpt/secure-headers](https://github.com/bepsvpt/secure-headers) | `composer require bepsvpt/secure-headers` |
| `Csrf\CsrfMiddleware` | [yiisoft/csrf](https://github.com/yiisoft/csrf) | `composer require yiisoft/csrf` |
| `Jwt\JwtAuthMiddleware` | [firebase/php-jwt](https://github.com/firebase/php-jwt) | `composer require firebase/php-jwt` |
| `RateLimit\RateLimitMiddleware` | [symfony/rate-limiter](https://symfony.com/doc/current/rate_limiter.html) | `composer require symfony/rate-limiter` |

## Installation

```bash
composer require pivotphp/security
```

Middlewares that build responses take a PSR-17 `ResponseFactoryInterface` (e.g.
`PivotPHP\Http\Factory\Psr17Factory` or `Nyholm\Psr7\Factory\Psr17Factory`).

## Recommended order

```text
TrustedProxy → SecurityHeaders → CORS → RateLimit → (body parsing) → CSRF → JWT → routes
```

- **TrustedProxy first**, so every later middleware sees the real client IP.
- **SecurityHeaders and CORS before anything that rejects**, so `401`/`403`/`429` responses still
  carry security and CORS headers (the browser can read the error).
- **CORS before authentication**: preflight requests carry no credentials.
- **Body parsing before CSRF**, so form fields are visible.

## CORS

```php
use PivotPHP\Security\Cors\CorsConfig;
use PivotPHP\Security\Cors\CorsMiddleware;

$cors = new CorsMiddleware($responseFactory, new CorsConfig(
    allowedOrigins: ['https://app.example.com'],
    allowCredentials: true,
));
```

| Option | Default | Notes |
|---|---|---|
| `allowedOrigins` | `[]` | Exact `scheme://host[:port]`, lower case, no path. `['*']` allows any origin. |
| `allowedMethods` | `GET, POST, PUT, PATCH, DELETE` | |
| `allowedHeaders` | `Content-Type, Authorization` | Request headers accepted in preflight. |
| `exposedHeaders` | `[]` | Response headers readable by the browser. |
| `allowCredentials` | `false` | |
| `maxAge` | `600` | Preflight cache in seconds; `null` omits the header. |

Behaviour:

- Requests without `Origin` pass through untouched.
- Preflight (`OPTIONS` + `Access-Control-Request-Method`) is answered by the middleware: `204` with
  `Access-Control-Allow-*` when origin, method and headers are allowed; `403` otherwise. The handler
  is never called.
- Actual requests always reach the handler; `Access-Control-Allow-Origin` is added only for allowed
  origins. `Vary: Origin` is added whenever the response depends on the origin.

> ⚠️ **Security:** `*` with `allowCredentials: true` is rejected at configuration. The `null`
> origin (sandboxed iframes, `file://`) cannot be allowed. CORS does not protect the server — it
> only tells browsers what other origins may read; authenticate and authorize every request.

## Trusted proxies

```php
use PivotPHP\Security\Proxy\TrustedProxyConfig;
use PivotPHP\Security\Proxy\TrustedProxyMiddleware;

$proxy = new TrustedProxyMiddleware(new TrustedProxyConfig(
    trustedProxies: ['10.0.0.0/8', '2001:db8::/32'],
));

// later: $request->getAttribute('client_ip')
```

| Option | Default | Notes |
|---|---|---|
| `trustedProxies` | `[]` | IPv4/IPv6 addresses or CIDR ranges. |
| `header` | `X-Forwarded-For` | Comma-separated IP chain. |
| `attribute` | `client_ip` | Attribute receiving the resolved IP. |

The forwarding header is honoured **only** when `REMOTE_ADDR` is a trusted proxy. The chain is read
right to left, skipping trusted proxies; the first untrusted address is the client. A malformed entry
stops the walk. The attribute is not set when `REMOTE_ADDR` is missing or invalid.

> ⚠️ **Security:** never trust `X-Forwarded-For` from the internet. List only the proxies you run
> (load balancer, reverse proxy).

## Security headers

```php
use PivotPHP\Security\Headers\SecurityHeadersConfig;
use PivotPHP\Security\Headers\SecurityHeadersMiddleware;

$headers = new SecurityHeadersMiddleware(); // API defaults
```

Default headers (JSON API, OWASP REST guidance):

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Permitted-Cross-Domain-Policies: none
```

| Option | Default | Notes |
|---|---|---|
| `hsts`, `hstsMaxAge`, `hstsIncludeSubDomains`, `hstsPreload` | `true`, `31536000`, `true`, `false` | Preload requires subdomains and max-age ≥ 1 year. |
| `frameOptions` | `deny` | `deny` or `sameorigin`. |
| `referrerPolicy` | `strict-origin-when-cross-origin` | Any standard value. |
| `contentSecurityPolicy` | `default-src 'none'; frame-ancestors 'none'` | `bepsvpt/secure-headers` CSP array; `null` disables. |
| `overrides` | `[]` | Raw `bepsvpt/secure-headers` config (Permissions-Policy, COOP/COEP/CORP, reporting...). |

```php
new SecurityHeadersConfig(contentSecurityPolicy: [
    'default-src' => ['self' => true],
    'img-src' => ['allow' => ['https://cdn.example.com']],
]);
```

Headers already set by the application are kept. The deprecated `X-XSS-Protection` is not sent.
CSP nonces are not supported (the library keeps them in static state shared across requests).

> ⚠️ **Security:** an HTML application needs a CSP that matches its assets; the default is meant for
> APIs. Enable HSTS only on HTTPS-only hosts.

## CSRF

Needed when the API authenticates with **cookies** (session or JWT in a cookie). Pure bearer-token
APIs are not exposed to CSRF.

```php
use PivotPHP\Security\Csrf\CsrfMiddleware;
use Yiisoft\Csrf\Hmac\HmacCsrfToken;
use Yiisoft\Csrf\MaskedCsrfToken;

$token = new MaskedCsrfToken(new HmacCsrfToken($identityGenerator, $secret, 'sha256', 3600));
$csrf = new CsrfMiddleware($responseFactory, $token);

// render: $request->getAttribute('csrf_token')->getValue()
```

Token strategies come from `yiisoft/csrf`: `SynchronizerCsrfToken` (random token in a storage, e.g.
the session) or `HmacCsrfToken` (stateless, bound to an identity such as the session id). Wrap either
in `MaskedCsrfToken` when the token is rendered in HTML (BREACH mitigation).

| Option (`CsrfConfig`) | Default | Notes |
|---|---|---|
| `parameterName` | `_csrf` | Form field. |
| `headerName` | `X-CSRF-Token` | Header (SPA/AJAX). |
| `safeMethods` | `GET, HEAD, OPTIONS` | `POST/PUT/PATCH/DELETE` cannot be declared safe. |
| `attribute` | `csrf_token` | Attribute holding the token object. |
| `failureStatus` | `403` | Any 4xx. |

Every other method needs a valid token in the body field or header; otherwise the response is the
failure status and the handler is not called.

> ⚠️ **Security:** keep `GET` free of side effects — safe methods are never checked. Combine with
> `SameSite` cookies.

## JWT authentication

```php
use PivotPHP\Security\Jwt\JwtAuthMiddleware;
use PivotPHP\Security\Jwt\JwtConfig;

$auth = new JwtAuthMiddleware($responseFactory, new JwtConfig(
    key: $_ENV['JWT_SECRET'],          // ≥ 32 bytes for HS256
    algorithm: 'HS256',
    publicPaths: ['/health', '/docs/*'],
));

// in the handler: $request->getAttribute('user') — the claims as an array
```

| Option | Default | Notes |
|---|---|---|
| `key` | — | Secret (HS*) or public key / PEM (RS*, PS256, ES*, EdDSA). |
| `algorithm` | `HS256` | Exactly one algorithm is accepted. |
| `publicPaths` | `[]` | `fnmatch` patterns that skip authentication. |
| `cookieName` | `null` | Cookie read when `Authorization` is absent. |
| `issuer` | `null` | Required `iss`. |
| `audience` | `[]` | Accepted `aud` values (any match). |
| `leeway` | `0` | Clock skew in seconds. |
| `attribute` | `user` | Attribute receiving the claims. |

Signature, `exp`, `nbf` and `iat` are verified by `firebase/php-jwt` (non-numeric time claims are
rejected); `iss`/`aud` are verified here. Failures return `401` with `WWW-Authenticate: Bearer`.

> ⚠️ **Security:** empty secrets, secrets shorter than the hash output (32/48/64 bytes) and unknown
> algorithms are rejected at configuration. Load keys from the environment or a secret store, never
> from source code.

## Rate limiting

```php
use PivotPHP\Security\RateLimit\RateLimitConfig;
use PivotPHP\Security\RateLimit\RateLimitMiddleware;
use Symfony\Component\RateLimiter\RateLimiterFactory;

$limiter = new RateLimiterFactory(
    ['id' => 'login', 'policy' => 'sliding_window', 'limit' => 5, 'interval' => '1 minute'],
    $storage,      // e.g. CacheStorage over Redis
    $lockFactory,  // symfony/lock — required for correct counts under concurrency
);

$loginLimit = new RateLimitMiddleware($responseFactory, $limiter, new RateLimitConfig(keyPrefix: 'login:'));
```

| Option (`RateLimitConfig`) | Default | Notes |
|---|---|---|
| `keyPrefix` | `''` | One prefix per limit/route group. |
| `clientIpAttribute` | `client_ip` | Set by `TrustedProxyMiddleware`; falls back to `REMOTE_ADDR`. |
| `exposeHeaders` | `true` | `X-RateLimit-Limit`/`X-RateLimit-Remaining` on accepted responses. |

A fourth constructor argument accepts a custom key resolver
(`fn (ServerRequestInterface $r): ?string`, e.g. an API key). Over the limit: `429` with
`Retry-After`, `X-RateLimit-Limit` and `X-RateLimit-Remaining: 0`; the handler is not called.
Use one middleware instance per limit (e.g. a stricter one on `/login`).

> ⚠️ **Security:** with `InMemoryStorage` or without a `LockFactory`, limits are per process and
> concurrent requests can exceed them. Use a shared storage and a lock in production.

## Testing

```bash
composer test           # PHPUnit
composer phpstan        # PHPStan level 9
composer cs:check       # PSR-12
composer quality:check  # all of the above
```

## License

MIT — see [LICENSE](LICENSE).
