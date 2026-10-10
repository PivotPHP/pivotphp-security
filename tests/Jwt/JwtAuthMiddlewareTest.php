<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Jwt;

use Firebase\JWT\JWT;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Jwt\JwtAuthMiddleware;
use PivotPHP\Security\Jwt\JwtConfig;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

final class JwtAuthMiddlewareTest extends TestCase
{
    private const SECRET = 'a-32-bytes-long-secret-for-tests';

    private RecordingHandler $handler;

    protected function setUp(): void
    {
        $this->handler = new RecordingHandler();
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function token(array $claims = [], string $secret = self::SECRET, string $alg = 'HS256'): string
    {
        return JWT::encode($claims + ['sub' => 'u1', 'exp' => time() + 60], $secret, $alg);
    }

    /**
     * @param array<string, string> $headers
     */
    private function call(array $headers, ?JwtConfig $config = null, string $path = '/me'): ResponseInterface
    {
        $config ??= new JwtConfig(self::SECRET);

        return (new JwtAuthMiddleware(new Psr17Factory(), $config))
            ->process(new ServerRequest('GET', $path, $headers), $this->handler);
    }

    /**
     * SPEC-054: the claims reach the handler.
     */
    public function testValidTokenExposesClaimsToHandler(): void
    {
        $response = $this->call(['Authorization' => 'Bearer ' . self::token(['role' => 'admin'])]);

        self::assertSame(200, $response->getStatusCode());
        $user = $this->handler->attribute('user');
        self::assertIsArray($user);
        self::assertSame('u1', $user['sub']);
        self::assertSame('admin', $user['role']);
    }

    public function testMissingTokenFailsClosed(): void
    {
        $response = $this->call([]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls);
        self::assertSame('Bearer realm="api"', $response->getHeaderLine('WWW-Authenticate'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidTokens(): iterable
    {
        yield 'wrong secret' => [self::token([], str_repeat('x', 32))];
        yield 'expired' => [self::token(['exp' => time() - 10])];
        yield 'not yet valid' => [self::token(['nbf' => time() + 60])];
        yield 'string exp (SPEC-060)' => [
            JWT::urlsafeB64Encode('{"alg":"HS256","typ":"JWT"}') . '.'
            . JWT::urlsafeB64Encode('{"sub":"u1","exp":"1"}') . '.'
            . JWT::urlsafeB64Encode(hash_hmac('sha256', JWT::urlsafeB64Encode('{"alg":"HS256","typ":"JWT"}') . '.'
                . JWT::urlsafeB64Encode('{"sub":"u1","exp":"1"}'), self::SECRET, true)),
        ];
        yield 'alg none' => [
            JWT::urlsafeB64Encode('{"alg":"none","typ":"JWT"}') . '.' . JWT::urlsafeB64Encode('{"sub":"u1"}') . '.',
        ];
        yield 'garbage' => ['not.a.jwt'];
    }

    #[DataProvider('invalidTokens')]
    public function testInvalidTokenFailsClosed(string $token): void
    {
        $response = $this->call(['Authorization' => 'Bearer ' . $token]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->handler->calls);
        self::assertStringContainsString('invalid_token', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAlgorithmConfusionIsRejected(): void
    {
        $config = new JwtConfig(self::SECRET, 'HS256');
        $hs512 = JWT::encode(['sub' => 'u1'], str_repeat('s', 64), 'HS512');

        self::assertSame(401, $this->call(['Authorization' => 'Bearer ' . $hs512], $config)->getStatusCode());
    }

    /**
     * SPEC-055: public paths are honoured.
     */
    public function testPublicPathsSkipAuthentication(): void
    {
        $config = new JwtConfig(self::SECRET, publicPaths: ['/health', '/docs/*']);

        self::assertSame(200, $this->call([], $config, '/health')->getStatusCode());
        self::assertSame(200, $this->call([], $config, '/docs/openapi.json')->getStatusCode());
        self::assertSame(401, $this->call([], $config, '/healthz')->getStatusCode());
    }

    public function testTokenFromCookie(): void
    {
        $config = new JwtConfig(self::SECRET, cookieName: 'session');
        $request = (new ServerRequest('GET', '/me'))->withCookieParams(['session' => self::token()]);

        $response = (new JwtAuthMiddleware(new Psr17Factory(), $config))->process($request, $this->handler);

        self::assertSame(200, $response->getStatusCode());
    }

    public function testIssuerAndAudienceAreEnforced(): void
    {
        $config = new JwtConfig(self::SECRET, issuer: 'https://auth.example', audience: ['api']);

        $ok = self::token(['iss' => 'https://auth.example', 'aud' => ['web', 'api']]);
        self::assertSame(200, $this->call(['Authorization' => 'Bearer ' . $ok], $config)->getStatusCode());

        $badIss = self::token(['iss' => 'https://evil.example', 'aud' => 'api']);
        self::assertSame(401, $this->call(['Authorization' => 'Bearer ' . $badIss], $config)->getStatusCode());

        $badAud = self::token(['iss' => 'https://auth.example', 'aud' => 'web']);
        self::assertSame(401, $this->call(['Authorization' => 'Bearer ' . $badAud], $config)->getStatusCode());
    }

    public function testLeewayIsAppliedAndRestored(): void
    {
        $config = new JwtConfig(self::SECRET, leeway: 30);
        $token = self::token(['exp' => time() - 10]);

        self::assertSame(200, $this->call(['Authorization' => 'Bearer ' . $token], $config)->getStatusCode());
        self::assertSame(0, JWT::$leeway);
    }

    /**
     * SPEC-060: empty or short secrets cannot be configured.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function weakKeys(): iterable
    {
        yield 'empty' => ['', 'HS256'];
        yield 'short HS256' => ['short-secret', 'HS256'];
        yield 'short HS512' => [str_repeat('k', 32), 'HS512'];
        yield 'unknown algorithm' => [self::SECRET, 'none'];
    }

    #[DataProvider('weakKeys')]
    public function testWeakConfigurationIsRejected(string $key, string $algorithm): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new JwtConfig($key, $algorithm);
    }

    public function testRsaTokensAreVerifiedWithThePublicKey(): void
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($private);
        openssl_pkey_export($private, $privatePem);
        $details = openssl_pkey_get_details($private);
        self::assertIsArray($details);
        self::assertIsString($privatePem);

        $config = new JwtConfig((string) $details['key'], 'RS256');
        $token = JWT::encode(['sub' => 'u1', 'exp' => time() + 60], $privatePem, 'RS256');

        self::assertSame(200, $this->call(['Authorization' => 'Bearer ' . $token], $config)->getStatusCode());
    }
}
