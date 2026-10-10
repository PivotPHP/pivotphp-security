<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Headers;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Headers\SecurityHeadersConfig;
use PivotPHP\Security\Headers\SecurityHeadersMiddleware;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SecurityHeadersMiddlewareTest extends TestCase
{
    /**
     * SPEC-075: modern defaults, no deprecated X-XSS-Protection.
     */
    public function testDefaultsTargetAJsonApi(): void
    {
        $response = (new SecurityHeadersMiddleware())->process(new ServerRequest('GET', '/'), new RecordingHandler());

        self::assertSame('max-age=31536000; includeSubDomains', $response->getHeaderLine('Strict-Transport-Security'));
        self::assertSame('nosniff', $response->getHeaderLine('X-Content-Type-Options'));
        self::assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        self::assertSame('strict-origin-when-cross-origin', $response->getHeaderLine('Referrer-Policy'));
        self::assertSame(
            "default-src 'none'; frame-ancestors 'none'",
            $response->getHeaderLine('Content-Security-Policy')
        );
        self::assertFalse($response->hasHeader('X-XSS-Protection'));
        self::assertFalse($response->hasHeader('Permissions-Policy'));
    }

    public function testHeadersSetByTheApplicationAreKept(): void
    {
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, ['Content-Security-Policy' => "default-src 'self'"]);
            }
        };

        $response = (new SecurityHeadersMiddleware())->process(new ServerRequest('GET', '/'), $handler);

        self::assertSame("default-src 'self'", $response->getHeaderLine('Content-Security-Policy'));
    }

    public function testOptionsAreApplied(): void
    {
        $middleware = new SecurityHeadersMiddleware(new SecurityHeadersConfig(
            hsts: false,
            frameOptions: 'sameorigin',
            referrerPolicy: 'no-referrer',
            contentSecurityPolicy: null,
            overrides: ['cross-origin-opener-policy' => 'same-origin'],
        ));

        $headers = $middleware->headers();

        self::assertArrayNotHasKey('Strict-Transport-Security', $headers);
        self::assertArrayNotHasKey('Content-Security-Policy', $headers);
        self::assertSame('SAMEORIGIN', $headers['X-Frame-Options']);
        self::assertSame('no-referrer', $headers['Referrer-Policy']);
        self::assertSame('same-origin', $headers['Cross-Origin-Opener-Policy']);
    }

    public function testCustomCsp(): void
    {
        $headers = (new SecurityHeadersMiddleware(new SecurityHeadersConfig(
            contentSecurityPolicy: [
                'default-src' => ['self' => true],
                'img-src' => ['allow' => ['https://cdn.example']],
            ],
        )))->headers();

        self::assertSame("default-src 'self'; img-src https://cdn.example", $headers['Content-Security-Policy']);
    }

    public function testPreloadRequiresSubDomainsAndLongMaxAge(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new SecurityHeadersConfig(hstsIncludeSubDomains: false, hstsPreload: true);
    }

    public function testInvalidFrameOptionsIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new SecurityHeadersConfig(frameOptions: 'allow-from https://x');
    }

    public function testInvalidReferrerPolicyIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new SecurityHeadersConfig(referrerPolicy: 'never');
    }
}
