<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Csrf;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Csrf\CsrfConfig;
use PivotPHP\Security\Csrf\CsrfMiddleware;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Yiisoft\Csrf\CsrfTokenInterface;
use Yiisoft\Csrf\Hmac\HmacCsrfToken;
use Yiisoft\Csrf\Hmac\IdentityGenerator\CsrfTokenIdentityGeneratorInterface;
use Yiisoft\Csrf\MaskedCsrfToken;
use Yiisoft\Csrf\Synchronizer\Generator\RandomCsrfTokenGenerator;
use Yiisoft\Csrf\Synchronizer\Storage\CsrfTokenStorageInterface;
use Yiisoft\Csrf\Synchronizer\SynchronizerCsrfToken;

final class CsrfMiddlewareTest extends TestCase
{
    private CsrfTokenInterface $token;
    private RecordingHandler $handler;

    protected function setUp(): void
    {
        $storage = new class implements CsrfTokenStorageInterface {
            private ?string $token = null;

            public function get(): ?string
            {
                return $this->token;
            }

            public function set(string $token): void
            {
                $this->token = $token;
            }

            public function remove(): void
            {
                $this->token = null;
            }
        };

        $this->token = new SynchronizerCsrfToken(new RandomCsrfTokenGenerator(), $storage);
        $this->handler = new RecordingHandler();
    }

    private function middleware(?CsrfConfig $config = null): CsrfMiddleware
    {
        return new CsrfMiddleware(new Psr17Factory(), $this->token, $config);
    }

    public function testSafeMethodPassesAndExposesTheToken(): void
    {
        $response = $this->middleware()->process(new ServerRequest('GET', '/form'), $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame($this->token, $this->handler->attribute('csrf_token'));
    }

    /**
     * SPEC-067: a legitimate POST with a valid token (form field) is accepted.
     */
    public function testValidTokenInBodyIsAccepted(): void
    {
        $request = (new ServerRequest('POST', '/form'))->withParsedBody(['_csrf' => $this->token->getValue()]);

        $response = $this->middleware()->process($request, $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(1, $this->handler->calls);
    }

    public function testValidTokenInHeaderIsAccepted(): void
    {
        $request = new ServerRequest('DELETE', '/item/1', ['X-CSRF-Token' => $this->token->getValue()]);

        self::assertSame(200, $this->middleware()->process($request, $this->handler)->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsafeMethods(): iterable
    {
        yield 'POST' => ['POST'];
        yield 'PUT' => ['PUT'];
        yield 'PATCH' => ['PATCH'];
        yield 'DELETE' => ['DELETE'];
    }

    /**
     * SPEC-067: every state-changing method is protected, not only POST.
     */
    #[DataProvider('unsafeMethods')]
    public function testUnsafeMethodWithoutTokenFailsClosed(string $method): void
    {
        $response = $this->middleware()->process(new ServerRequest($method, '/x'), $this->handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls);
        self::assertSame('{"error":"Invalid CSRF token"}', (string) $response->getBody());
    }

    public function testWrongTokenFailsClosed(): void
    {
        $this->token->getValue();
        $request = new ServerRequest('POST', '/x', ['X-CSRF-Token' => 'forged']);

        self::assertSame(403, $this->middleware()->process($request, $this->handler)->getStatusCode());
    }

    public function testObjectParsedBodyIsValidatedAndOriginalRequestReachesHandler(): void
    {
        $body = (object) ['_csrf' => $this->token->getValue(), 'name' => 'x'];
        $request = (new ServerRequest('POST', '/form'))->withParsedBody($body);

        $response = $this->middleware()->process($request, $this->handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame($body, $this->handler->request?->getParsedBody());
    }

    public function testCustomNamesAndStatus(): void
    {
        $config = new CsrfConfig(parameterName: 'token', headerName: 'X-XSRF', failureStatus: 419);

        $ok = (new ServerRequest('POST', '/x', ['X-XSRF' => $this->token->getValue()]));
        self::assertSame(200, $this->middleware($config)->process($ok, $this->handler)->getStatusCode());

        $bad = new ServerRequest('POST', '/x', ['X-CSRF-Token' => $this->token->getValue()]);
        self::assertSame(419, $this->middleware($config)->process($bad, $this->handler)->getStatusCode());
    }

    public function testStatelessHmacAndMaskedTokens(): void
    {
        $identity = new class implements CsrfTokenIdentityGeneratorInterface {
            public string $id = 'session-a';

            public function generate(): string
            {
                return $this->id;
            }
        };
        $this->token = new MaskedCsrfToken(new HmacCsrfToken($identity, str_repeat('k', 32), 'sha256', 300));

        $value = $this->token->getValue();
        self::assertNotSame($value, $this->token->getValue(), 'masked tokens differ on every render');

        $request = new ServerRequest('POST', '/x', ['X-CSRF-Token' => $value]);
        self::assertSame(200, $this->middleware()->process($request, $this->handler)->getStatusCode());

        $identity->id = 'session-b';
        self::assertSame(403, $this->middleware()->process($request, new RecordingHandler())->getStatusCode());
    }

    public function testStateChangingMethodsCannotBeDeclaredSafe(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new CsrfConfig(safeMethods: ['GET', 'post']);
    }
}
