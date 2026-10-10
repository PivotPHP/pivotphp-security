<?php

declare(strict_types=1);

namespace PivotPHP\Security\Headers;

use Bepsvpt\SecureHeaders\SecureHeaders;
use PivotPHP\Security\Exception\MissingDependencyException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionClass;

/**
 * Adds security headers to every response (adapter for `bepsvpt/secure-headers`).
 *
 * The header set is computed once, when the middleware is built. Headers the
 * application already set on the response are kept (never overwritten).
 *
 * CSP nonces from `bepsvpt/secure-headers` are not supported: they rely on
 * static state shared across requests.
 */
final class SecurityHeadersMiddleware implements MiddlewareInterface
{
    /** @var array<string, string> */
    private readonly array $headers;

    public function __construct(?SecurityHeadersConfig $config = null)
    {
        if (!class_exists(SecureHeaders::class)) {
            throw MissingDependencyException::forPackage(self::class, 'bepsvpt/secure-headers');
        }

        $config ??= new SecurityHeadersConfig();

        $libraryConfig = array_replace_recursive(
            self::libraryDefaults(),
            $config->toLibraryConfig(),
            $config->overrides
        );

        $headers = [];
        foreach ((new SecureHeaders($libraryConfig))->headers() as $name => $value) {
            if (is_string($name) && is_string($value) && $value !== '') {
                $headers[$name] = $value;
            }
        }

        $this->headers = $headers;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        foreach ($this->headers as $name => $value) {
            if (!$response->hasHeader($name)) {
                $response = $response->withHeader($name, $value);
            }
        }

        return $response;
    }

    /**
     * Headers this middleware adds (useful for inspection and tests).
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * The library reads several keys without defaults, so its shipped
     * configuration is used as the base.
     *
     * @return array<string, mixed>
     */
    private static function libraryDefaults(): array
    {
        $file = dirname((string) (new ReflectionClass(SecureHeaders::class))->getFileName(), 2)
            . '/config/secure-headers.php';

        /** @var array<string, mixed> $defaults */
        $defaults = require $file;

        return $defaults;
    }
}
