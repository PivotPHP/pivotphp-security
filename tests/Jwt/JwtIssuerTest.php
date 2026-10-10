<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Jwt;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Jwt\JwtAuthMiddleware;
use PivotPHP\Security\Jwt\JwtConfig;
use PivotPHP\Security\Jwt\JwtIssuer;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class JwtIssuerTest extends TestCase
{
    private const SECRET = 'a-32-bytes-long-secret-for-tests';

    public function testIssuedTokenIsAcceptedByTheMiddleware(): void
    {
        $config = new JwtConfig(self::SECRET, issuer: 'https://auth.example', audience: ['api']);
        $token = (new JwtIssuer($config))->issue(['sub' => 'u1', 'role' => 'admin'], 60);

        $handler = new RecordingHandler();
        $response = (new JwtAuthMiddleware(new Psr17Factory(), $config))
            ->process(new ServerRequest('GET', '/me', ['Authorization' => 'Bearer ' . $token]), $handler);

        self::assertSame(200, $response->getStatusCode());
        $user = $handler->attribute('user');
        self::assertIsArray($user);
        self::assertSame('u1', $user['sub']);
        self::assertSame('admin', $user['role']);
        self::assertSame('https://auth.example', $user['iss']);
        self::assertSame('api', $user['aud']);
    }

    public function testTimeClaimsAreSetFromTheClock(): void
    {
        $token = (new JwtIssuer(new JwtConfig(self::SECRET)))->issue(['sub' => 'u1'], 300, 1_000_000);

        JWT::$timestamp = 1_000_100;
        try {
            $claims = (array) JWT::decode($token, new Key(self::SECRET, 'HS256'));
        } finally {
            JWT::$timestamp = null;
        }

        self::assertSame(1_000_000, $claims['iat']);
        self::assertSame(1_000_000, $claims['nbf']);
        self::assertSame(1_000_300, $claims['exp']);
        self::assertArrayNotHasKey('iss', $claims);
        self::assertArrayNotHasKey('aud', $claims);
    }

    public function testExpiredIssuedTokenIsRejected(): void
    {
        $config = new JwtConfig(self::SECRET);
        $token = (new JwtIssuer($config))->issue(['sub' => 'u1'], 60, time() - 120);

        $response = (new JwtAuthMiddleware(new Psr17Factory(), $config))
            ->process(new ServerRequest('GET', '/me', ['Authorization' => 'Bearer ' . $token]), new RecordingHandler());

        self::assertSame(401, $response->getStatusCode());
    }

    public function testMultipleAudiencesAreIssuedAsList(): void
    {
        $config = new JwtConfig(self::SECRET, audience: ['web', 'api']);
        $claims = (array) JWT::decode((new JwtIssuer($config))->issue(['sub' => 'u1']), new Key(self::SECRET, 'HS256'));

        self::assertSame(['web', 'api'], $claims['aud']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function reservedClaims(): iterable
    {
        yield 'exp' => ['exp'];
        yield 'iat' => ['iat'];
        yield 'nbf' => ['nbf'];
        yield 'iss' => ['iss'];
        yield 'aud' => ['aud'];
    }

    #[DataProvider('reservedClaims')]
    public function testReservedClaimsCannotBeOverridden(string $claim): void
    {
        $this->expectException(InvalidConfigurationException::class);

        (new JwtIssuer(new JwtConfig(self::SECRET)))->issue([$claim => 'x']);
    }

    public function testNonPositiveTtlIsRejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        (new JwtIssuer(new JwtConfig(self::SECRET)))->issue(['sub' => 'u1'], 0);
    }

    public function testAsymmetricAlgorithmRequiresPrivateKey(): void
    {
        $details = $this->rsaKeyPair();

        $this->expectException(InvalidConfigurationException::class);

        new JwtIssuer(new JwtConfig($details['public'], 'RS256'));
    }

    public function testRsaTokensRoundTrip(): void
    {
        $keys = $this->rsaKeyPair();
        $config = new JwtConfig($keys['public'], 'RS256');
        $token = (new JwtIssuer($config, $keys['private']))->issue(['sub' => 'u1']);

        $response = (new JwtAuthMiddleware(new Psr17Factory(), $config))
            ->process(new ServerRequest('GET', '/me', ['Authorization' => 'Bearer ' . $token]), new RecordingHandler());

        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * @return array{public: string, private: string}
     */
    private function rsaKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $private);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($private);
        self::assertIsString($details['key']);

        return ['public' => $details['key'], 'private' => $private];
    }
}
