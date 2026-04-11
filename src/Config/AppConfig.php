<?php

declare(strict_types=1);

namespace MonkeysLegion\Config;

use MonkeysLegion\Config\Providers\{
    AuthProvider,
    ValidationProvider,
    CacheProvider,
    CliProvider,
    DatabaseProvider,
    EventProvider,
    FilesProvider,
    HttpFactoryProvider,
    MailProvider,
    MiddlewareProvider,
    OpenApiProvider,
    QueueProvider,
    RoutingProvider,
    ServiceProviderInterface,
    SessionProvider,
    TelemetryProvider,
    TemplateProvider,
};
use MonkeysLegion\DI\ContainerBuilder;

/**
 * Modular DI definitions shipped by the framework.
 *
 * Loads domain-specific ServiceProviders based on the current execution
 * context (HTTP vs CLI) for minimal overhead per request.
 */
final class AppConfig
{
    /**
     * Deterministic list of providers loaded in dependency order.
     *
     * @var class-string<ServiceProviderInterface>[]
     */
    private static array $providers = [
        HttpFactoryProvider::class,
        CacheProvider::class,
        TelemetryProvider::class,
        EventProvider::class,
        DatabaseProvider::class,
        SessionProvider::class,
        RoutingProvider::class,
        MiddlewareProvider::class,
        AuthProvider::class,
        TemplateProvider::class,
        ValidationProvider::class,
        OpenApiProvider::class,
        FilesProvider::class,
        QueueProvider::class,
        CliProvider::class,
        MailProvider::class,
    ];

    /**
     * Build all DI definitions for the current context.
     *
     * @return array<string, callable|object>
     */
    public function __invoke(): array
    {
        $context = PHP_SAPI === 'cli' ? 'cli' : 'http';

        // Logger always loads first (it has its own sub-provider chain)
        $definitions = (new LoggerConfig())();

        foreach (self::$providers as $class) {
            /** @var ServiceProviderInterface $provider */
            $provider = new $class();

            $providerContext = $provider->context();
            if ($providerContext === 'all' || $providerContext === $context) {
                $definitions = array_merge($definitions, $provider->getDefinitions());
            }
        }

        return $definitions;
    }

    /**
     * Called by your bootstrap to add framework defaults.
     *
     * Backward-compatible entry point used by HttpBootstrap::buildContainer().
     */
    public static function register(ContainerBuilder $builder): void
    {
        // Fix for OAuthService expecting legacy JwtService class
        if (!class_exists('MonkeysLegion\Auth\JwtService')) {
            class_alias(\MonkeysLegion\Auth\Service\JwtService::class, 'MonkeysLegion\Auth\JwtService');
        }

        $builder->addDefinitions((new self())());
    }

    /**
     * Get the list of registered provider class names.
     *
     * Useful for tooling, cache compilation, and debugging.
     *
     * @return class-string<ServiceProviderInterface>[]
     */
    public static function getProviders(): array
    {
        return self::$providers;
    }
}
