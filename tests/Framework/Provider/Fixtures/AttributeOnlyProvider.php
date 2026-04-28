<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider\Fixtures;

use MonkeysLegion\Core\Attribute\Provider;

/**
 * Fixture: provider with #[Provider] attribute but NO interface.
 * Should be discovered when attributeRequired=true but skipped if interface-only.
 */
#[Provider(priority: 5, context: 'cli')]
final class AttributeOnlyProvider
{
    public function getDefinitions(): array
    {
        return [
            'fixture.attr_only' => fn(): string => 'attr_only_value',
        ];
    }
}
