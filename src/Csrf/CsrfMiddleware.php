<?php

declare(strict_types=1);

namespace PivotPHP\Security\Csrf;

use PivotPHP\Security\Exception\MissingDependencyException;
use PivotPHP\Security\Support\ErrorResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Csrf\CsrfTokenInterface;
use Yiisoft\Csrf\CsrfTokenMiddleware;

/**
 * CSRF protection (adapter for `yiisoft/csrf`).
 *
 * The token strategy is the `yiisoft/csrf` token you inject:
 * - `SynchronizerCsrfToken` — random token stored in the session;
 * - `HmacCsrfToken` — stateless HMAC token bound to an identity;
 * - wrap either in `MaskedCsrfToken` to mitigate BREACH when the token is rendered in HTML.
 *
 * The token object is exposed to handlers in the `csrf_token` attribute (call
 * `getValue()` to render it). Requests with an unsafe method and a missing or
 * invalid token never reach the handler and receive `403` (configurable).
 *
 * Body parsing must run before this middleware so form fields are visible.
 */
final class CsrfMiddleware implements MiddlewareInterface
{
    private readonly CsrfTokenMiddleware $inner;
    private readonly CsrfConfig $config;

    public function __construct(
        ResponseFactoryInterface $responseFactory,
        private readonly CsrfTokenInterface $token,
        ?CsrfConfig $config = null,
    ) {
        if (!class_exists(CsrfTokenMiddleware::class)) {
            throw MissingDependencyException::forPackage(self::class, 'yiisoft/csrf');
        }

        $this->config = $config ?? new CsrfConfig();

        $failure = new class ($responseFactory, $this->config->failureStatus) implements RequestHandlerInterface {
            public function __construct(
                private readonly ResponseFactoryInterface $factory,
                private readonly int $status,
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return ErrorResponse::create($this->factory, $this->status, 'Invalid CSRF token');
            }
        };

        $this->inner = (new CsrfTokenMiddleware($responseFactory, $token, $failure))
            ->withParameterName($this->config->parameterName)
            ->withHeaderName($this->config->headerName)
            ->withSafeMethods($this->config->safeMethods);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $request = $request->withAttribute($this->config->attribute, $this->token);

        // yiisoft/csrf reads the parsed body as an array; PSR-7 also allows objects.
        // Validate against an array view, but hand the original request to the handler.
        $body = $request->getParsedBody();
        if (!is_object($body)) {
            return $this->inner->process($request, $handler);
        }

        $original = $request;
        $next = new class ($handler, $original) implements RequestHandlerInterface {
            public function __construct(
                private readonly RequestHandlerInterface $handler,
                private readonly ServerRequestInterface $original,
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->handler->handle($this->original);
            }
        };

        return $this->inner->process($request->withParsedBody(get_object_vars($body)), $next);
    }
}
