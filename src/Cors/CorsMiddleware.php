<?php

declare(strict_types=1);

namespace PivotPHP\Security\Cors;

use PivotPHP\Security\Support\ErrorResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * CORS (Fetch standard) middleware.
 *
 * - Requests without `Origin` are not CORS requests and pass through untouched.
 * - Preflight requests (`OPTIONS` + `Access-Control-Request-Method`) are answered
 *   here and never reach the handler: `204` when allowed, `403` otherwise.
 * - Actual requests always reach the handler (CORS is enforced by the browser);
 *   `Access-Control-Allow-*` headers are added only for allowed origins.
 * - `Vary: Origin` is added whenever the response depends on the origin.
 *
 * Register it before authentication so preflight requests need no credentials.
 */
final class CorsMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly CorsConfig $config,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if ($origin === '') {
            return $handler->handle($request);
        }

        if ($this->isPreflight($request)) {
            return $this->preflight($request, $origin);
        }

        $response = $handler->handle($request);

        if (!$this->config->allowsOrigin($origin)) {
            return $this->vary($response, ['Origin']);
        }

        $response = $this->withAllowOrigin($response, $origin);

        if ($this->config->exposedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Expose-Headers',
                implode(', ', $this->config->exposedHeaders)
            );
        }

        return $response;
    }

    private function isPreflight(ServerRequestInterface $request): bool
    {
        return strtoupper($request->getMethod()) === 'OPTIONS'
            && $request->hasHeader('Access-Control-Request-Method');
    }

    private function preflight(ServerRequestInterface $request, string $origin): ResponseInterface
    {
        $vary = ['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'];

        if (!$this->config->allowsOrigin($origin)) {
            return $this->vary($this->forbidden('CORS origin not allowed'), $vary);
        }

        $method = strtoupper($request->getHeaderLine('Access-Control-Request-Method'));
        if (!in_array($method, $this->config->allowedMethods, true)) {
            return $this->vary($this->forbidden('CORS method not allowed'), $vary);
        }

        $requestedHeaders = $this->requestedHeaders($request);
        foreach ($requestedHeaders as $header) {
            if (!in_array($header, $this->config->allowedHeaders, true)) {
                return $this->vary($this->forbidden('CORS header not allowed'), $vary);
            }
        }

        $response = $this->withAllowOrigin($this->responseFactory->createResponse(204), $origin)
            ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->config->allowedMethods));

        if ($this->config->allowedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Allow-Headers',
                implode(', ', $this->config->allowedHeaders)
            );
        }

        if ($this->config->maxAge !== null) {
            $response = $response->withHeader('Access-Control-Max-Age', (string) $this->config->maxAge);
        }

        return $this->vary($response, $vary);
    }

    /**
     * @return list<string> lower-cased header names
     */
    private function requestedHeaders(ServerRequestInterface $request): array
    {
        $line = $request->getHeaderLine('Access-Control-Request-Headers');
        if (trim($line) === '') {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn (string $header): string => strtolower(trim($header)),
            explode(',', $line)
        ), static fn (string $header): bool => $header !== ''));
    }

    private function withAllowOrigin(ResponseInterface $response, string $origin): ResponseInterface
    {
        if ($this->config->allowsAnyOrigin()) {
            return $response->withHeader('Access-Control-Allow-Origin', '*');
        }

        $response = $this->vary($response->withHeader('Access-Control-Allow-Origin', $origin), ['Origin']);

        if ($this->config->allowCredentials) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        return $response;
    }

    private function forbidden(string $message): ResponseInterface
    {
        return ErrorResponse::create($this->responseFactory, 403, $message);
    }

    /**
     * Adds header names to `Vary` without duplicating existing entries.
     *
     * @param list<string> $names
     */
    private function vary(ResponseInterface $response, array $names): ResponseInterface
    {
        if ($this->config->allowsAnyOrigin()) {
            return $response;
        }

        $current = array_values(array_filter(array_map(
            'trim',
            explode(',', $response->getHeaderLine('Vary'))
        ), static fn (string $value): bool => $value !== ''));

        $lower = array_map('strtolower', $current);
        foreach ($names as $name) {
            if (!in_array(strtolower($name), $lower, true)) {
                $current[] = $name;
                $lower[] = strtolower($name);
            }
        }

        return $response->withHeader('Vary', implode(', ', $current));
    }
}
