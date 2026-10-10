<?php

declare(strict_types=1);

namespace PivotPHP\Security\Csrf;

use PivotPHP\Security\Exception\InvalidConfigurationException;

/**
 * Immutable CSRF configuration.
 *
 * Every method not listed in `$safeMethods` (POST, PUT, PATCH, DELETE, ...)
 * must carry a valid token in the body field or in the header.
 */
final class CsrfConfig
{
    /** @var list<string> */
    public readonly array $safeMethods;

    /**
     * @param list<string> $safeMethods methods that never require a token
     * @param string       $attribute   request attribute receiving the `CsrfTokenInterface`
     */
    public function __construct(
        public readonly string $parameterName = '_csrf',
        public readonly string $headerName = 'X-CSRF-Token',
        array $safeMethods = ['GET', 'HEAD', 'OPTIONS'],
        public readonly string $attribute = 'csrf_token',
        public readonly int $failureStatus = 403,
    ) {
        if ($parameterName === '' || $headerName === '' || $attribute === '') {
            throw new InvalidConfigurationException('CSRF: parameterName, headerName and attribute must not be empty.');
        }

        $safeMethods = array_values(array_unique(array_map('strtoupper', $safeMethods)));
        $unsafe = array_intersect($safeMethods, ['POST', 'PUT', 'PATCH', 'DELETE']);
        if ($unsafe !== []) {
            throw new InvalidConfigurationException(sprintf(
                'CSRF: state-changing methods cannot be declared safe (%s).',
                implode(', ', $unsafe)
            ));
        }

        if ($failureStatus < 400 || $failureStatus > 499) {
            throw new InvalidConfigurationException('CSRF: failureStatus must be a 4xx status code.');
        }

        $this->safeMethods = $safeMethods;
    }
}
