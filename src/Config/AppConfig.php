<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use MonkeysLegion\Config\Providers\ApexProvider;
use MonkeysLegion\Config\Providers\AuthProvider;
use MonkeysLegion\Config\Providers\CacheProvider;
use MonkeysLegion\Config\Providers\CliProvider;
use MonkeysLegion\Config\Providers\DatabaseProvider;
use MonkeysLegion\Config\Providers\DevToolsProvider;
use MonkeysLegion\Config\Providers\EventProvider;
use MonkeysLegion\Config\Providers\FilesProvider;
use MonkeysLegion\Config\Providers\HttpFactoryProvider;
use MonkeysLegion\Config\Providers\I18nProvider;
use MonkeysLegion\Config\Providers\LoggerProvider;
use MonkeysLegion\Config\Providers\MiddlewareProvider;
use MonkeysLegion\Config\Providers\OpenApiProvider;
use MonkeysLegion\Config\Providers\QueueProvider;
use MonkeysLegion\Config\Providers\RoutingProvider;
use MonkeysLegion\Config\Providers\ScheduleProvider;
use MonkeysLegion\Config\Providers\ServiceProviderInterface;
use MonkeysLegion\Config\Providers\SessionProvider;
use MonkeysLegion\Config\Providers\SocketsProvider;
use MonkeysLegion\Config\Providers\TelemetryProvider;
use MonkeysLegion\Config\Providers\TemplateProvider;
use MonkeysLegion\Config\Providers\ValidationProvider;

/**
 * Central aggregator of all framework service providers.
 *
 * Invoked by Application::boot() to collect DI definitions.
 * Each provider is context-filtered (http / cli / all).
 *
 * @see \MonkeysLegion\Framework\Application
 */
final class AppConfig
{
    /**
     * Provider registry in boot order.
     *
     * @var array<class-string<ServiceProviderInterface>>
     */
    private const array PROVIDERS = [
        // ─── Core (always loaded) ───────────────────────────────────
        LoggerProvider::class,
        EventProvider::class,
        CacheProvider::class,
        DatabaseProvider::class,
        ValidationProvider::class,
        I18nProvider::class,
        QueueProvider::class,
        FilesProvider::class,
        TelemetryProvider::class,
        ApexProvider::class,
        SocketsProvider::class,

        // ─── HTTP-only ──────────────────────────────────────────────
        HttpFactoryProvider::class,
        RoutingProvider::class,
        SessionProvider::class,
        AuthProvider::class,
        MiddlewareProvider::class,
        TemplateProvider::class,
        OpenApiProvider::class,
        DevToolsProvider::class,

        // ─── CLI-only ───────────────────────────────────────────────
        CliProvider::class,
        ScheduleProvider::class,
    ];

    /**
     * Aggregate DI definitions from all providers matching the given context.
     *
     * @param string $context 'http', 'cli', or 'all'
     * @return array<string, callable|object>
     */
    public function __invoke(string $context = 'http'): array
    {
        $definitions = [];

        foreach (self::PROVIDERS as $providerClass) {
            /** @var ServiceProviderInterface $provider */
            $provider = new $providerClass();

            $providerContext = $provider->context();

            // Skip if context doesn't match
            if ($providerContext !== 'all' && $providerContext !== $context) {
                continue;
            }

            $definitions = array_merge($definitions, $provider->getDefinitions());
        }

        return $definitions;
    }

    /**
     * Get all registered provider class names.
     *
     * @return array<class-string<ServiceProviderInterface>>
     */
    public static function getProviders(): array
    {
        return self::PROVIDERS;
    }
}
