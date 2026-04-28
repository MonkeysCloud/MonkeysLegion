<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider\Fixtures;

use MonkeysLegion\Contracts\AbstractServiceProvider;

/**
 * Fixture: concrete provider with interface only (no #[Provider] attribute).
 */
final class InterfaceOnlyProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            'fixture.interface_only' => fn(): string => 'from_interface',
        ];
    }
}
