<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Cors;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Cors\CorsConfig;
use PivotPHP\Security\Cors\CorsMiddleware;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class CorsMiddlewareTest extends TestCase
{
    private RecordingHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new RecordingHandler();
    }

    private function middleware(CorsConfig $config): CorsMiddleware
    {
        return new CorsMiddleware(new Psr17Factory(), $config);
    }

    private function credentialsConfig(): CorsConfig
    {
        return new CorsConfig(allowedOrigins: ['https://app.example.com'], allowCredentials: true);
    }

    public function testRequestWithoutOriginPassesThroughUntouched(): void
    {
        $response = $this->middleware($this->credentialsConfig())
            ->process(new ServerRequest('GET', '/x'), $this->handler);

        self::assertSame(1, $this->handler->calls);
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Vary'));
    }

    public function testAllowedOriginWithCredentialsEchoesOriginAndVaries(): void
    {
        $request = new ServerRequest('GET', '/x', ['Origin' => 'https://app.example.com']);
        $response = $this->middleware($this->credentialsConfig())->process($request, $this->handler);

        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame('Origin', $response->getHeaderLine('Vary'));
    }

    /**
     * SPEC-064: a disallowed origin must not receive `*` nor credentials.
     */
    public function testDisallowedOriginGetsNoCorsHeaders(): void
    {
        $request = new ServerRequest('GET', '/x', ['Origin' => 'https://evil.example']);
        $response = $this->middleware($this->credentialsConfig())->process($request, $this->handler);

        self::assertSame(1, $this->handler->calls);
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
        self::assertSame('Origin', $response->getHeaderLine('Vary'));
    }

    public function testNullOriginIsNotAllowed(): void
    {
        $request = new ServerRequest('GET', '/x', ['Origin' => 'null']);
        $response = $this->middleware($this->credentialsConfig())->process($request, $this->handler);

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    public function testWildcardWithCredentialsIsRejectedAtConfiguration(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new CorsConfig(allowedOrigins: ['*'], allowCredentials: true);
    }

    public function testWildcardOriginSendsStarWithoutVary(): void
    {
        $request = new ServerRequest('GET', '/x', ['Origin' => 'https://any.example']);
        $response = $this->middleware(new CorsConfig(allowedOrigins: ['*']))->process($request, $this->handler);

        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
        self::assertFalse($response->hasHeader('Vary'));
    }

    /**
     * SPEC-063: the preflight is answered by the middleware, with headers, and never reaches the handler.
     */
    public function testAllowedPreflightIsAnsweredWithoutCallingTheHandler(): void
    {
        $request = new ServerRequest('OPTIONS', '/x', [
            'Origin' => 'https://app.example.com',
            'Access-Control-Request-Method' => 'PUT',
            'Access-Control-Request-Headers' => 'content-type, Authorization',
        ]);
        $response = $this->middleware($this->credentialsConfig())->process($request, $this->handler);

        self::assertSame(0, $this->handler->calls);
        self::assertSame(204, $response->getStatusCode());
        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('GET, POST, PUT, PATCH, DELETE', $response->getHeaderLine('Access-Control-Allow-Methods'));
        self::assertSame('content-type, authorization', $response->getHeaderLine('Access-Control-Allow-Headers'));
        self::assertSame('600', $response->getHeaderLine('Access-Control-Max-Age'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame(
            'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
            $response->getHeaderLine('Vary')
        );
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function rejectedPreflights(): iterable
    {
        yield 'origin' => [['Origin' => 'https://evil.example', 'Access-Control-Request-Method' => 'GET']];
        yield 'method' => [['Origin' => 'https://app.example.com', 'Access-Control-Request-Method' => 'TRACE']];
        yield 'header' => [[
            'Origin' => 'https://app.example.com',
            'Access-Control-Request-Method' => 'GET',
            'Access-Control-Request-Headers' => 'X-Secret',
        ]];
    }

    /**
     * @param array<string, string> $headers
     */
    #[DataProvider('rejectedPreflights')]
    public function testRejectedPreflightFailsClosed(array $headers): void
    {
        $response = $this->middleware($this->credentialsConfig())
            ->process(new ServerRequest('OPTIONS', '/x', $headers), $this->handler);

        self::assertSame(0, $this->handler->calls);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    public function testPlainOptionsWithoutPreflightHeaderReachesHandler(): void
    {
        $request = new ServerRequest('OPTIONS', '/x', ['Origin' => 'https://app.example.com']);
        $this->middleware($this->credentialsConfig())->process($request, $this->handler);

        self::assertSame(1, $this->handler->calls);
    }

    public function testExposedHeadersAndExistingVaryArePreserved(): void
    {
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, ['Vary' => 'Accept-Encoding, origin']);
            }
        };

        $config = new CorsConfig(allowedOrigins: ['https://app.example.com'], exposedHeaders: ['X-Request-Id']);
        $request = new ServerRequest('GET', '/x', ['Origin' => 'https://app.example.com']);
        $response = $this->middleware($config)->process($request, $handler);

        self::assertSame('X-Request-Id', $response->getHeaderLine('Access-Control-Expose-Headers'));
        self::assertSame('Accept-Encoding, origin', $response->getHeaderLine('Vary'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidOrigins(): iterable
    {
        yield 'null' => ['null'];
        yield 'trailing slash' => ['https://app.example.com/'];
        yield 'path' => ['https://app.example.com/api'];
        yield 'no scheme' => ['app.example.com'];
        yield 'upper case' => ['https://App.example.com'];
        yield 'ftp' => ['ftp://app.example.com'];
    }

    #[DataProvider('invalidOrigins')]
    public function testInvalidOriginsAreRejectedAtConfiguration(string $origin): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new CorsConfig(allowedOrigins: [$origin]);
    }
}
