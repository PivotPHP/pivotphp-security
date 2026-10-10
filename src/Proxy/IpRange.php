<?php

declare(strict_types=1);

namespace PivotPHP\Security\Proxy;

/**
 * IPv4/IPv6 address and CIDR matching.
 *
 * @internal
 */
final class IpRange
{
    public static function isValid(string $range): bool
    {
        return self::parse($range) !== null;
    }

    public static function contains(string $range, string $ip): bool
    {
        $parsed = self::parse($range);
        $address = @inet_pton($ip);

        if ($parsed === null || $address === false) {
            return false;
        }

        [$network, $bits] = $parsed;

        if (strlen($network) !== strlen($address)) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        if (strncmp($network, $address, $bytes) !== 0) {
            return false;
        }

        $remainder = $bits % 8;
        if ($remainder === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($network[$bytes]) & $mask) === (ord($address[$bytes]) & $mask);
    }

    /**
     * @return array{0: string, 1: int}|null packed network address and prefix length
     */
    private static function parse(string $range): ?array
    {
        $parts = explode('/', $range, 2);
        $network = @inet_pton($parts[0]);

        if ($network === false) {
            return null;
        }

        $maxBits = strlen($network) * 8;

        if (!isset($parts[1])) {
            return [$network, $maxBits];
        }

        if (preg_match('/^\d{1,3}$/', $parts[1]) !== 1 || (int) $parts[1] > $maxBits) {
            return null;
        }

        return [$network, (int) $parts[1]];
    }
}
