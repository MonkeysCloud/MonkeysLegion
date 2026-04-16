<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\DI\Container;

/**
 * Base class that provides sensible defaults for service providers.
 *
 * Concrete providers only need to implement getDefinitions().
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

    /** Default: not deferred. */
    public function isDeferred(): bool
    {
        return false;
    }

    /** Default: no-op boot. */
    public function boot(Container $container): void
    {
        // Override in subclasses if post-build initialization is needed
    }
}
