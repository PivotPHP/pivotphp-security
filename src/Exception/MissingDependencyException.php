<?php

declare(strict_types=1);

namespace PivotPHP\Security\Exception;

use LogicException;

/**
 * Thrown when a middleware is used without the library it adapts.
 */
final class MissingDependencyException extends LogicException implements SecurityException
{
    public static function forPackage(string $middleware, string $package): self
    {
        return new self(sprintf(
            '%s requires the "%s" package. Install it with: composer require %s',
            $middleware,
            $package,
            $package
        ));
    }
}
