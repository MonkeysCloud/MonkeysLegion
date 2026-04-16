<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\DI\Container;

/**
 * Contract for modular service-provider classes.
 *
 * Each provider encapsulates a domain of DI definitions (e.g. Auth, Database,
 * Queue) and declares the context in which it should be loaded.
 */
interface ServiceProviderInterface
{
    /**
     * Return DI definitions for this domain.
     *
     * @return array<string, callable|object>
     */
    public function getDefinitions(): array;

    /**
     * Service IDs this provider registers (used for deferred loading).
     *
     * @return string[]
     */
    public function provides(): array;

    /**
     * Context in which this provider should be loaded.
     *
     * 'http' — only during HTTP requests
     * 'cli'  — only during CLI execution
     * 'all'  — always loaded
     */
    public function context(): string;

    /**
     * Whether this provider should be deferred (lazy-loaded).
     */
    public function isDeferred(): bool;

    /**
     * Post-build initialization hook.
     *
     * Called after the container has been fully built, allowing providers
     * to perform setup that depends on other services being registered.
     */
    public function boot(Container $container): void;
}
