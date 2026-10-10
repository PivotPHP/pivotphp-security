<?php

declare(strict_types=1);

namespace PivotPHP\Security\Tests\Proxy;

use Nyholm\Psr7\ServerRequest;
use PivotPHP\Security\Exception\InvalidConfigurationException;
use PivotPHP\Security\Proxy\IpRange;
use PivotPHP\Security\Proxy\TrustedProxyConfig;
use PivotPHP\Security\Proxy\TrustedProxyMiddleware;
use PivotPHP\Security\Tests\Support\RecordingHandler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TrustedProxyMiddlewareTest extends TestCase
{
    private function resolve(string $remote, ?string $forwarded, TrustedProxyConfig $config): mixed
    {
        $headers = $forwarded === null ? [] : ['X-Forwarded-For' => $forwarded];
        $handler = new RecordingHandler();

        (new TrustedProxyMiddleware($config))->process(
            new ServerRequest('GET', '/', $headers, null, '1.1', ['REMOTE_ADDR' => $remote]),
            $handler
        );

        return $handler->attribute('client_ip');
    }

    /**
     * SPEC-065: a direct client cannot choose its IP through X-Forwarded-For.
     */
    public function testForwardedHeaderIsIgnoredFromUntrustedPeer(): void
    {
        self::assertSame('203.0.113.7', $this->resolve('203.0.113.7', '8.8.8.8', new TrustedProxyConfig()));
        self::assertSame(
            '203.0.113.7',
            $this->resolve('203.0.113.7', '8.8.8.8', new TrustedProxyConfig(['10.0.0.0/8']))
        );
    }

    public function testClientIsTakenFromTrustedProxy(): void
    {
        $config = new TrustedProxyConfig(['10.0.0.0/8']);

        self::assertSame('198.51.100.4', $this->resolve('10.0.0.5', '198.51.100.4', $config));
    }

    public function testChainIsWalkedRightToLeftSkippingTrustedHops(): void
    {
        $config = new TrustedProxyConfig(['10.0.0.0/8', '192.0.2.10']);

        // the left-most entry is attacker-controlled; the first untrusted hop from the right wins
        self::assertSame('198.51.100.4', $this->resolve('10.0.0.5', '1.2.3.4, 198.51.100.4, 192.0.2.10', $config));
    }

    public function testMalformedEntryStopsAtLastTrustedHop(): void
    {
        $config = new TrustedProxyConfig(['10.0.0.0/8']);

        self::assertSame('10.0.0.5', $this->resolve('10.0.0.5', 'not-an-ip', $config));
        self::assertSame('10.1.1.1', $this->resolve('10.0.0.5', '198.51.100.4, garbage, 10.1.1.1', $config));
    }

    public function testMissingHeaderFromTrustedProxyFallsBackToRemoteAddr(): void
    {
        self::assertSame('10.0.0.5', $this->resolve('10.0.0.5', null, new TrustedProxyConfig(['10.0.0.0/8'])));
    }

    public function testInvalidRemoteAddrLeavesAttributeUnset(): void
    {
        self::assertNull($this->resolve('garbage', '8.8.8.8', new TrustedProxyConfig(['10.0.0.0/8'])));
    }

    public function testIpv6RangesAreSupported(): void
    {
        $config = new TrustedProxyConfig(['fd00::/8']);

        self::assertSame('2001:db8::1', $this->resolve('fd12::1', '2001:db8::1', $config));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function ranges(): iterable
    {
        yield 'exact v4' => ['192.0.2.1', '192.0.2.1', true];
        yield 'exact v4 miss' => ['192.0.2.1', '192.0.2.2', false];
        yield '/8 hit' => ['10.0.0.0/8', '10.255.1.1', true];
        yield '/8 miss' => ['10.0.0.0/8', '11.0.0.1', false];
        yield '/12 partial byte hit' => ['172.16.0.0/12', '172.31.255.255', true];
        yield '/12 partial byte miss' => ['172.16.0.0/12', '172.32.0.1', false];
        yield '/0' => ['0.0.0.0/0', '8.8.8.8', true];
        yield 'v6 /64 hit' => ['2001:db8::/64', '2001:db8::abcd', true];
        yield 'v6 /64 miss' => ['2001:db8::/64', '2001:db8:0:1::1', false];
        yield 'family mismatch' => ['10.0.0.0/8', '::ffff:10.0.0.1', false];
    }

    #[DataProvider('ranges')]
    public function testIpRangeMatching(string $range, string $ip, bool $expected): void
    {
        self::assertSame($expected, IpRange::contains($range, $ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidRanges(): iterable
    {
        yield 'text' => ['localhost'];
        yield 'prefix too long' => ['10.0.0.0/33'];
        yield 'negative prefix' => ['10.0.0.0/-1'];
        yield 'empty' => [''];
    }

    #[DataProvider('invalidRanges')]
    public function testInvalidTrustedProxyIsRejected(string $range): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new TrustedProxyConfig([$range]);
    }
}
