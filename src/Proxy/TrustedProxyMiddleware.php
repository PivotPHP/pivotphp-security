<?php

declare(strict_types=1);

namespace PivotPHP\Security\Proxy;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Resolves the real client IP into a request attribute (default `client_ip`).
 *
 * The forwarding header is honoured **only** when the direct peer
 * (`REMOTE_ADDR`) is a trusted proxy. The chain is then walked from right to
 * left, skipping trusted proxies; the first untrusted address is the client.
 * A malformed entry stops the walk and the last trusted hop is used, so a
 * client can never choose its own IP by sending the header.
 *
 * The attribute is not set when `REMOTE_ADDR` is missing or invalid.
 */
final class TrustedProxyMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly TrustedProxyConfig $config)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $clientIp = $this->resolve($request);

        if ($clientIp !== null) {
            $request = $request->withAttribute($this->config->attribute, $clientIp);
        }

        return $handler->handle($request);
    }

    private function resolve(ServerRequestInterface $request): ?string
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        if (!is_string($remote) || filter_var($remote, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        if (!$this->config->isTrusted($remote)) {
            return $remote;
        }

        $chain = array_map('trim', explode(',', $request->getHeaderLine($this->config->header)));
        $client = $remote;

        foreach (array_reverse($chain) as $hop) {
            if ($hop === '' || filter_var($hop, FILTER_VALIDATE_IP) === false) {
                break;
            }

            $client = $hop;

            if (!$this->config->isTrusted($hop)) {
                break;
            }
        }

        return $client;
    }
}
