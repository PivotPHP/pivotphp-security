<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Support;

use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Final handler that records the request it received and answers 200.
 */
final class RecordingHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $request = null;

    public int $calls = 0;

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;
        $this->calls++;

        return new Response(200, ['Content-Type' => 'text/plain'], 'handler');
    }

    public function attribute(string $name): mixed
    {
        return $this->request?->getAttribute($name);
    }
}
