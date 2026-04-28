<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider\Fixtures;

use MonkeysLegion\Contracts\AbstractServiceProvider;

/**
 * Fixture: abstract base provider — should be skipped by scanner.
 */
abstract class AbstractBaseProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            'fixture.abstract' => fn(): string => 'should_not_appear',
        ];
    }
}
