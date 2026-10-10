<?php

declare(strict_types=1);

namespace PivotPHP\Security\Support;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Builds the JSON rejection responses returned by the middlewares.
 *
 * @internal
 */
final class ErrorResponse
{
    public static function create(ResponseFactoryInterface $factory, int $status, string $message): ResponseInterface
    {
        $response = $factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json; charset=utf-8');

        $response->getBody()->write((string) json_encode(['error' => $message], JSON_THROW_ON_ERROR));

        return $response;
    }
}
