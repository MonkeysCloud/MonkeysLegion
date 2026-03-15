<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

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
}
