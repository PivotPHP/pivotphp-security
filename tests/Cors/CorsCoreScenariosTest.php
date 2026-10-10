<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Cors;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Cors\CorsConfig;
use PivotPHP\Security\Cors\CorsMiddleware;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * Scenarios ported from pivotphp-core
 * (tests/Middleware/Http/CorsMiddlewareTest.php, tests/Core/CorsMiddlewareTestPsr15.php,
 * tests/Integration/Middleware/Psr15MiddlewareUseTest.php).
 *
 * Expectations follow the Fetch standard; where the core asserted a wrong behaviour
 * the corrected expectation is noted (see SPEC-063/064).
 */
final class CorsCoreScenariosTest extends TestCase
{
    private function process(CorsConfig $config, ServerRequest $request): ResponseInterface
    {
        return (new CorsMiddleware(new Psr17Factory(), $config))->process($request, new RecordingHandler());
    }

    private static function preflight(string $origin, string $method = 'GET', string $headers = ''): ServerRequest
    {
        $request = new ServerRequest('OPTIONS', '/api', [
            'Origin' => $origin,
            'Access-Control-Request-Method' => $method,
        ]);

        return $headers === '' ? $request : $request->withHeader('Access-Control-Request-Headers', $headers);
    }

    /**
     * Core: testCorsHeadersWithDefaultsPsr15 / testDefaultConfiguration.
     * The core defaulted to "*"; here the default allows no origin (explicit opt-in).
     */
    public function testDefaultConfigurationAllowsNoOrigin(): void
    {
        $response = $this->process(
            new CorsConfig(),
            new ServerRequest('GET', '/api', ['Origin' => 'https://example.com'])
        );

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    /**
     * Core: testCorsWithCustomOptionsPsr15 / testCorsHeadersConsistency.
     * Allow-Methods/Allow-Headers/Max-Age belong to the preflight only (not to the actual response).
     */
    public function testCustomOptionsAreConsistentBetweenPreflightAndActualRequest(): void
    {
        $config = new CorsConfig(
            allowedOrigins: ['https://trusted.com'],
            allowedMethods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type', 'X-API-Key'],
            allowCredentials: true,
            maxAge: 7200,
        );

        $preflight = $this->process($config, self::preflight('https://trusted.com', 'POST', 'X-API-Key'));
        self::assertSame(204, $preflight->getStatusCode());
        self::assertSame('https://trusted.com', $preflight->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('GET, POST', $preflight->getHeaderLine('Access-Control-Allow-Methods'));
        self::assertSame('content-type, x-api-key', $preflight->getHeaderLine('Access-Control-Allow-Headers'));
        self::assertSame('true', $preflight->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame('7200', $preflight->getHeaderLine('Access-Control-Max-Age'));

        $actual = $this->process($config, new ServerRequest('GET', '/api', ['Origin' => 'https://trusted.com']));
        self::assertSame('https://trusted.com', $actual->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $actual->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertFalse($actual->hasHeader('Access-Control-Allow-Methods'));
        self::assertFalse($actual->hasHeader('Access-Control-Max-Age'));
    }

    /**
     * Core: testCorsWithArrayOfOrigins / testMultipleCorsRequests.
     * The core answered a disallowed origin with "Access-Control-Allow-Origin: null" (SPEC-064).
     */
    public function testOriginListIsEvaluatedPerRequestWithoutLeakingState(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://app1.com', 'https://app2.com']);
        $middleware = new CorsMiddleware(new Psr17Factory(), $config);
        $handler = new RecordingHandler();

        $first = $middleware->process(new ServerRequest('GET', '/', ['Origin' => 'https://app1.com']), $handler);
        $second = $middleware->process(new ServerRequest('GET', '/', ['Origin' => 'https://app2.com']), $handler);
        $denied = $middleware->process(new ServerRequest('GET', '/', ['Origin' => 'https://malicious.com']), $handler);

        self::assertSame('https://app1.com', $first->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('https://app2.com', $second->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertFalse($denied->hasHeader('Access-Control-Allow-Origin'));
        self::assertSame('Origin', $denied->getHeaderLine('Vary'));
    }

    /**
     * Core: testCorsWithCredentialsDisabled.
     */
    public function testCredentialsDisabledOmitsHeader(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://example.com']);

        $actual = $this->process($config, new ServerRequest('GET', '/', ['Origin' => 'https://example.com']));
        $preflight = $this->process($config, self::preflight('https://example.com'));

        self::assertFalse($actual->hasHeader('Access-Control-Allow-Credentials'));
        self::assertFalse($preflight->hasHeader('Access-Control-Allow-Credentials'));
    }

    /**
     * Core: testCorsWithCustomMethods / testCorsWithCustomHeaders (the "...AsString" variants
     * do not apply: options are typed lists).
     */
    public function testCustomMethodsAndHeadersRestrictThePreflight(): void
    {
        $config = new CorsConfig(
            allowedOrigins: ['https://example.com'],
            allowedMethods: ['GET', 'PATCH'],
            allowedHeaders: ['X-Custom-Header'],
        );

        $patch = $this->process($config, self::preflight('https://example.com', 'PATCH'));
        $delete = $this->process($config, self::preflight('https://example.com', 'DELETE'));

        self::assertSame(204, $patch->getStatusCode());
        self::assertSame(403, $delete->getStatusCode());
        self::assertSame(
            204,
            $this->process($config, self::preflight('https://example.com', 'GET', 'x-custom-header'))->getStatusCode()
        );
        self::assertSame(
            403,
            $this->process($config, self::preflight('https://example.com', 'GET', 'Authorization'))->getStatusCode()
        );
    }

    /**
     * Core: testCorsWithCustomMaxAge (plus: `null` omits the header).
     */
    public function testMaxAge(): void
    {
        $custom = $this->process(
            new CorsConfig(allowedOrigins: ['https://example.com'], maxAge: 3600),
            self::preflight('https://example.com')
        );
        $omitted = $this->process(
            new CorsConfig(allowedOrigins: ['https://example.com'], maxAge: null),
            self::preflight('https://example.com')
        );

        self::assertSame('3600', $custom->getHeaderLine('Access-Control-Max-Age'));
        self::assertFalse($omitted->hasHeader('Access-Control-Max-Age'));
    }

    /**
     * Core: testCorsWithExposeHeaders / testCorsWithoutExposeHeaders.
     */
    public function testExposeHeaders(): void
    {
        $request = new ServerRequest('GET', '/', ['Origin' => 'https://example.com']);

        $with = $this->process(
            new CorsConfig(allowedOrigins: ['https://example.com'], exposedHeaders: ['X-Total-Count', 'X-Page-Count']),
            $request
        );
        $without = $this->process(new CorsConfig(allowedOrigins: ['https://example.com']), $request);

        self::assertSame('X-Total-Count, X-Page-Count', $with->getHeaderLine('Access-Control-Expose-Headers'));
        self::assertFalse($without->hasHeader('Access-Control-Expose-Headers'));
    }

    /**
     * Core: testRequestWithoutOriginHeader.
     * The core added "Access-Control-Allow-Origin: *" to non-CORS requests; they now pass untouched.
     */
    public function testRequestWithoutOriginHasNoCorsHeaders(): void
    {
        $response = $this->process(new CorsConfig(allowedOrigins: ['*']), new ServerRequest('GET', '/'));

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    /**
     * Core: testOptionsPreflightRequest / testOptionsPreflightRequestPsr15 / testCoreCorsMiddlewareViaUse.
     * The core returned 200 for preflight; it is now 204 and never reaches the handler (SPEC-063).
     */
    public function testPreflightIsAnsweredByTheMiddleware(): void
    {
        $handler = new RecordingHandler();
        $response = (new CorsMiddleware(new Psr17Factory(), new CorsConfig(allowedOrigins: ['*'])))
            ->process(self::preflight('https://example.com', 'POST', 'Content-Type'), $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame(0, $handler->calls);
    }

    /**
     * Core: testEdgeCases — empty configuration must not break requests.
     */
    public function testEmptyConfigurationPassesRequestsThrough(): void
    {
        $config = new CorsConfig(allowedOrigins: [], allowedMethods: [], allowedHeaders: []);

        $actual = $this->process($config, new ServerRequest('GET', '/', ['Origin' => 'https://example.com']));
        $preflight = $this->process($config, self::preflight('https://example.com'));

        self::assertSame(200, $actual->getStatusCode());
        self::assertSame(403, $preflight->getStatusCode());
    }
}
