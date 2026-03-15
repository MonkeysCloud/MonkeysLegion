<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Validation\AttributeValidator;
use MonkeysLegion\Validation\DtoBinder;
use MonkeysLegion\Validation\Middleware\ValidationMiddleware;
use MonkeysLegion\Validation\ValidatorInterface;

final class ValidationProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            ValidatorInterface::class => fn() => new AttributeValidator(),

            DtoBinder::class => fn($c) => new DtoBinder(
                $c->get(ValidatorInterface::class)
            ),

            ValidationMiddleware::class => fn($c) => new ValidationMiddleware(
                $c->get(DtoBinder::class),
                []
            ),
        ];
    }
}
