<?php

declare(strict_types=1);

namespace PivotPHP\Security\RateLimit;

use Closure;
use PivotPHP\Security\Exception\MissingDependencyException;
use PivotPHP\Security\Support\ErrorResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;

/**
 * Rate limiting (adapter for `symfony/rate-limiter`).
 *
 * The client key is, in order: the custom resolver (if given), the
 * `client_ip` attribute set by `TrustedProxyMiddleware`, then `REMOTE_ADDR`.
 * Requests over the limit never reach the handler and receive `429` with
 * `Retry-After`, `X-RateLimit-Limit` and `X-RateLimit-Remaining`.
 *
 * Use one middleware instance per limit (e.g. a stricter one on `/login`).
 * Under concurrency, give the factory a `LockFactory` (symfony/lock) and a
 * shared storage, otherwise parallel requests can exceed the limit.
 */
final class RateLimitMiddleware implements MiddlewareInterface
{
    private readonly RateLimitConfig $config;

    /** @var (Closure(ServerRequestInterface): ?string)|null */
    private readonly ?Closure $keyResolver;

    /**
     * @param (callable(ServerRequestInterface): ?string)|null $keyResolver custom client key
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly RateLimiterFactory $limiterFactory,
        ?RateLimitConfig $config = null,
        ?callable $keyResolver = null,
    ) {
        if (!class_exists(RateLimiterFactory::class)) {
            throw MissingDependencyException::forPackage(self::class, 'symfony/rate-limiter');
        }

        $this->config = $config ?? new RateLimitConfig();
        $this->keyResolver = $keyResolver === null ? null : Closure::fromCallable($keyResolver);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $limit = $this->limiterFactory->create($this->config->keyPrefix . $this->clientKey($request))->consume();

        if (!$limit->isAccepted()) {
            $retryAfter = max(0, $limit->getRetryAfter()->getTimestamp() - time());

            return ErrorResponse::create($this->responseFactory, 429, 'Too Many Requests')
                ->withHeader('Retry-After', (string) $retryAfter)
                ->withHeader('X-RateLimit-Limit', (string) $limit->getLimit())
                ->withHeader('X-RateLimit-Remaining', '0');
        }

        $response = $handler->handle($request);

        if (!$this->config->exposeHeaders) {
            return $response;
        }

        return $response
            ->withHeader('X-RateLimit-Limit', (string) $limit->getLimit())
            ->withHeader('X-RateLimit-Remaining', (string) $limit->getRemainingTokens());
    }

    private function clientKey(ServerRequestInterface $request): string
    {
        if ($this->keyResolver !== null) {
            $key = ($this->keyResolver)($request);
            if ($key !== null && $key !== '') {
                return $key;
            }
        }

        $ip = $request->getAttribute($this->config->clientIpAttribute);
        if (is_string($ip) && $ip !== '') {
            return $ip;
        }

        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($remote) && $remote !== '' ? $remote : 'unknown';
    }
}
