<?php

declare(strict_types=1);

namespace PivotPHP\Security\Exception;

use InvalidArgumentException;

/**
 * Thrown when a security configuration is invalid or unsafe.
 *
 * Configurations are validated when they are built, so a misconfiguration
 * fails at boot instead of silently weakening protection at runtime.
 */
final class InvalidConfigurationException extends InvalidArgumentException implements SecurityException
{
}
