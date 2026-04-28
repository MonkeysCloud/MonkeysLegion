<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider\Fixtures;

use MonkeysLegion\Contracts\AbstractServiceProvider;
use MonkeysLegion\Core\Attribute\Provider;

/**
 * Fixture: concrete provider with #[Provider] attribute.
 */
#[Provider(priority: 10, context: 'all')]
final class AttributeProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            'fixture.attribute' => fn(): string => 'from_attribute',
        ];
    }
}
