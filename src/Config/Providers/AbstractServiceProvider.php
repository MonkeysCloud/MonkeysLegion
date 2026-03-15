<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

/**
 * Base class that provides sensible defaults for providers.
 */
abstract class AbstractServiceProvider implements ServiceProviderInterface
{
    /** Default: load in all contexts. */
    public function context(): string
    {
        return 'all';
    }

    /** Default: derive from getDefinitions() keys. */
    public function provides(): array
    {
        return array_keys($this->getDefinitions());
    }
}
