<?php

declare(strict_types=1);

namespace PivotPHP\Security\Jwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PivotPHP\Security\Exception\MissingDependencyException;
use PivotPHP\Security\Support\ErrorResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;

/**
 * JWT bearer authentication (adapter for `firebase/php-jwt`).
 *
 * - Public paths pass through without a token.
 * - The token is read from `Authorization: Bearer <token>`, then from the
 *   configured cookie.
 * - Signature, algorithm, `exp`, `nbf` and `iat` are verified by
 *   `firebase/php-jwt`; `iss` and `aud` are verified here when configured.
 * - On success the claims (as an array) are stored in the `user` attribute and
 *   the **same** request is passed to the handler.
 * - Any failure returns `401` with `WWW-Authenticate: Bearer` and never
 *   reaches the handler.
 */
final class JwtAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly JwtConfig $config,
    ) {
        if (!class_exists(JWT::class)) {
            throw MissingDependencyException::forPackage(self::class, 'firebase/php-jwt');
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->config->isPublicPath($request->getUri()->getPath())) {
            return $handler->handle($request);
        }

        $token = $this->extractToken($request);
        if ($token === null) {
            return $this->unauthorized('Bearer realm="api"', 'Authentication required');
        }

        $claims = $this->decode($token);
        if ($claims === null || !$this->hasValidIssuer($claims) || !$this->hasValidAudience($claims)) {
            return $this->unauthorized('Bearer realm="api", error="invalid_token"', 'Invalid token');
        }

        return $handler->handle($request->withAttribute($this->config->attribute, $claims));
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $authorization = $request->getHeaderLine('Authorization');
        if (preg_match('/^Bearer\s+(\S+)$/i', $authorization, $matches) === 1) {
            return $matches[1];
        }

        if ($this->config->cookieName !== null) {
            $cookie = $request->getCookieParams()[$this->config->cookieName] ?? null;
            if (is_string($cookie) && $cookie !== '') {
                return $cookie;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function decode(string $token): ?array
    {
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->config->leeway;

        try {
            $payload = JWT::decode($token, new Key($this->config->key, $this->config->algorithm));
            $claims = json_decode((string) json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return null;
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        if (!is_array($claims)) {
            return null;
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function hasValidIssuer(array $claims): bool
    {
        return $this->config->issuer === null || ($claims['iss'] ?? null) === $this->config->issuer;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function hasValidAudience(array $claims): bool
    {
        if ($this->config->audience === []) {
            return true;
        }

        $aud = $claims['aud'] ?? null;
        $values = is_array($aud) ? $aud : [$aud];

        foreach ($values as $value) {
            if (is_string($value) && in_array($value, $this->config->audience, true)) {
                return true;
            }
        }

        return false;
    }

    private function unauthorized(string $challenge, string $message): ResponseInterface
    {
        return ErrorResponse::create($this->responseFactory, 401, $message)
            ->withHeader('WWW-Authenticate', $challenge);
    }
}
