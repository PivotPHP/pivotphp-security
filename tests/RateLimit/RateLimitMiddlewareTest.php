<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\RateLimit;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\RateLimit\RateLimitConfig;
use PivotPHP\Security\RateLimit\RateLimitMiddleware;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

final class RateLimitMiddlewareTest extends TestCase
{
    private function middleware(
        int $limit = 2,
        ?RateLimitConfig $config = null,
        ?callable $resolver = null,
    ): RateLimitMiddleware {
        $factory = new RateLimiterFactory(
            ['id' => 'test', 'policy' => 'fixed_window', 'limit' => $limit, 'interval' => '1 minute'],
            new InMemoryStorage()
        );

        return new RateLimitMiddleware(new Psr17Factory(), $factory, $config, $resolver);
    }

    private static function request(string $remote, ?string $clientIp = null): ServerRequestInterface
    {
        $request = new ServerRequest('POST', '/login', [], null, '1.1', ['REMOTE_ADDR' => $remote]);

        return $clientIp === null ? $request : $request->withAttribute('client_ip', $clientIp);
    }

    private static function send(RateLimitMiddleware $middleware, ServerRequestInterface $request): ResponseInterface
    {
        return $middleware->process($request, new RecordingHandler());
    }

    public function testRequestsWithinTheLimitExposeHeaders(): void
    {
        $middleware = $this->middleware();

        $first = self::send($middleware, self::request('203.0.113.1'));

        self::assertSame(200, $first->getStatusCode());
        self::assertSame('2', $first->getHeaderLine('X-RateLimit-Limit'));
        self::assertSame('1', $first->getHeaderLine('X-RateLimit-Remaining'));
    }

    public function testOverTheLimitFailsClosedWith429(): void
    {
        $middleware = $this->middleware();
        $handler = new RecordingHandler();

        $middleware->process(self::request('203.0.113.1'), $handler);
        $middleware->process(self::request('203.0.113.1'), $handler);
        $blocked = $middleware->process(self::request('203.0.113.1'), $handler);

        self::assertSame(2, $handler->calls);
        self::assertSame(429, $blocked->getStatusCode());
        self::assertSame('0', $blocked->getHeaderLine('X-RateLimit-Remaining'));
        self::assertGreaterThan(0, (int) $blocked->getHeaderLine('Retry-After'));
        self::assertLessThanOrEqual(60, (int) $blocked->getHeaderLine('Retry-After'));
    }

    public function testClientsAreLimitedIndependently(): void
    {
        $middleware = $this->middleware(1);

        self::assertSame(200, self::send($middleware, self::request('203.0.113.1'))->getStatusCode());
        self::assertSame(200, self::send($middleware, self::request('203.0.113.2'))->getStatusCode());
        self::assertSame(429, self::send($middleware, self::request('203.0.113.1'))->getStatusCode());
    }

    /**
     * SPEC-065: the key comes from the trusted client_ip attribute, not from raw headers.
     */
    public function testClientIpAttributeTakesPrecedenceOverRemoteAddr(): void
    {
        $middleware = $this->middleware(1);

        self::assertSame(200, self::send($middleware, self::request('10.0.0.5', '198.51.100.1'))->getStatusCode());
        self::assertSame(200, self::send($middleware, self::request('10.0.0.5', '198.51.100.2'))->getStatusCode());
        self::assertSame(429, self::send($middleware, self::request('10.0.0.9', '198.51.100.1'))->getStatusCode());
    }

    public function testForwardedHeaderAloneDoesNotChangeTheKey(): void
    {
        $middleware = $this->middleware(1);

        self::send($middleware, self::request('203.0.113.1')->withHeader('X-Forwarded-For', '1.1.1.1'));
        $second = self::send($middleware, self::request('203.0.113.1')->withHeader('X-Forwarded-For', '2.2.2.2'));

        self::assertSame(429, $second->getStatusCode());
    }

    public function testCustomResolverAndHiddenHeaders(): void
    {
        $middleware = $this->middleware(
            1,
            new RateLimitConfig(exposeHeaders: false),
            static fn (ServerRequestInterface $request): string => $request->getHeaderLine('X-Api-Key')
        );

        $ok = self::send($middleware, self::request('203.0.113.1')->withHeader('X-Api-Key', 'a'));
        self::assertFalse($ok->hasHeader('X-RateLimit-Limit'));
        $otherKey = self::send($middleware, self::request('203.0.113.1')->withHeader('X-Api-Key', 'b'));
        $sameKey = self::send($middleware, self::request('203.0.113.9')->withHeader('X-Api-Key', 'a'));

        self::assertSame(200, $otherKey->getStatusCode());
        self::assertSame(429, $sameKey->getStatusCode());
    }
}
