<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Provider\Fixtures;

/**
 * Fixture: plain PHP class — no attribute, no interface.
 * Should never be included in any discovery mode.
 */
final class PlainClass
{
    public function doSomething(): string
    {
        return 'not_a_provider';
    }
}
