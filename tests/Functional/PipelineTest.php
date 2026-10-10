<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Functional;

use Firebase\JWT\JWT;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Cors\CorsConfig;
use PivotPHP\Security\Cors\CorsMiddleware;
use PivotPHP\Security\Headers\SecurityHeadersMiddleware;
use PivotPHP\Security\Jwt\JwtAuthMiddleware;
use PivotPHP\Security\Jwt\JwtConfig;
use PivotPHP\Security\Proxy\TrustedProxyConfig;
use PivotPHP\Security\Proxy\TrustedProxyMiddleware;
use PivotPHP\Security\RateLimit\RateLimitMiddleware;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * The recommended order, composed in a plain PSR-15 pipeline:
 * proxy → headers → CORS → rate limit → JWT → handler.
 */
final class PipelineTest extends TestCase
{
    private const SECRET = 'a-32-bytes-long-secret-for-tests';

    private RecordingHandler $handler;
    private RequestHandlerInterface $pipeline;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->handler = new RecordingHandler();

        $middlewares = [
            new TrustedProxyMiddleware(new TrustedProxyConfig(['10.0.0.0/8'])),
            new SecurityHeadersMiddleware(),
            new CorsMiddleware($factory, new CorsConfig(['https://app.example.com'], allowCredentials: true)),
            new RateLimitMiddleware($factory, new RateLimiterFactory(
                ['id' => 'api', 'policy' => 'fixed_window', 'limit' => 3, 'interval' => '1 minute'],
                new InMemoryStorage()
            )),
            new JwtAuthMiddleware($factory, new JwtConfig(self::SECRET, publicPaths: ['/health'])),
        ];

        $this->pipeline = array_reduce(
            array_reverse($middlewares),
            static fn (RequestHandlerInterface $next, MiddlewareInterface $middleware): RequestHandlerInterface =>
                new class ($middleware, $next) implements RequestHandlerInterface {
                    public function __construct(
                        private readonly MiddlewareInterface $middleware,
                        private readonly RequestHandlerInterface $next,
                    ) {
                    }

                    public function handle(ServerRequestInterface $request): ResponseInterface
                    {
                        return $this->middleware->process($request, $this->next);
                    }
                },
            $this->handler
        );
    }

    /**
     * @param array<string, string> $headers
     */
    private function send(string $method, string $path, array $headers = []): ResponseInterface
    {
        return $this->pipeline->handle(
            new ServerRequest($method, $path, $headers, null, '1.1', ['REMOTE_ADDR' => '10.0.0.5'])
        );
    }

    public function testPreflightNeedsNoCredentialsAndCarriesSecurityHeaders(): void
    {
        $response = $this->send('OPTIONS', '/me', [
            'Origin' => 'https://app.example.com',
            'Access-Control-Request-Method' => 'GET',
            'Access-Control-Request-Headers' => 'authorization',
        ]);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('nosniff', $response->getHeaderLine('X-Content-Type-Options'));
        self::assertSame(0, $this->handler->calls);
    }

    public function testAuthenticatedRequestReachesHandlerWithUserAndClientIp(): void
    {
        $token = JWT::encode(['sub' => 'u1', 'exp' => time() + 60], self::SECRET, 'HS256');

        $response = $this->send('GET', '/me', [
            'Authorization' => 'Bearer ' . $token,
            'Origin' => 'https://app.example.com',
            'X-Forwarded-For' => '198.51.100.4',
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('198.51.100.4', $this->handler->attribute('client_ip'));
        self::assertSame(['sub' => 'u1', 'exp' => $this->claim('exp')], $this->handler->attribute('user'));
        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('2', $response->getHeaderLine('X-RateLimit-Remaining'));
    }

    public function testRejectionsStillCarrySecurityAndCorsHeaders(): void
    {
        $response = $this->send('GET', '/me', ['Origin' => 'https://app.example.com']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testRateLimitAppliesPerResolvedClientIp(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->send('GET', '/health', ['X-Forwarded-For' => '198.51.100.4']);
        }

        $blocked = $this->send('GET', '/health', ['X-Forwarded-For' => '198.51.100.4']);
        $other = $this->send('GET', '/health', ['X-Forwarded-For' => '198.51.100.5']);

        self::assertSame(429, $blocked->getStatusCode());
        self::assertSame(200, $other->getStatusCode());
    }

    private function claim(string $name): mixed
    {
        $user = $this->handler->attribute('user');

        return is_array($user) ? ($user[$name] ?? null) : null;
    }
}
