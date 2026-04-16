<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

/**
 * @deprecated Use Application::create(basePath: __DIR__)->run() instead.
 *
 * This class exists only for backward compatibility during the v1 → v2 migration.
 * It will be removed in v3.0.
 */
final class HttpBootstrap
{
    /**
     * Legacy entry point — delegates to the new Application boot flow.
     *
     * @deprecated Use bootstrap/app.php instead.
     */
    public static function run(string $basePath = ''): void
    {
        trigger_error(
            'HttpBootstrap::run() is deprecated. Use Application::create()->run() instead.',
            E_USER_DEPRECATED,
        );

        $basePath = $basePath !== '' ? $basePath : dirname(__DIR__, 2);

        Application::create(basePath: $basePath)->run();
    }
}
