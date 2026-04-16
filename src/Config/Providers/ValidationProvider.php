<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Validation\Contracts\ValidatorInterface;
use MonkeysLegion\Validation\DtoBinder;
use MonkeysLegion\Validation\Validator;

/**
 * Validation engine and DTO binder provider.
 */
final class ValidationProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            Validator::class          => fn(): Validator => new Validator(),
            ValidatorInterface::class => fn($c): Validator => $c->get(Validator::class),
            DtoBinder::class          => fn($c): DtoBinder => new DtoBinder(
                validator: $c->get(ValidatorInterface::class),
            ),
        ];
    }
}
