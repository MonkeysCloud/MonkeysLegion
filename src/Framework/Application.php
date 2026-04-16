<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework;

use MonkeysLegion\Config\AppConfig;
use MonkeysLegion\Config\ConfigLoader;
use MonkeysLegion\DI\Container;
use MonkeysLegion\DI\ContainerBuilder;
use MonkeysLegion\DI\CompiledContainerCache;
use MonkeysLegion\Framework\Provider\ProviderScanner;
use MonkeysLegion\Config\Providers\ServiceProviderInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Container\ContainerInterface;

/**
 * Central application orchestrator for MonkeysLegion v2.
 *
 * Provides a fluent builder API for configuring and booting the framework:
 *   Application::create(basePath: '/app')
 *       ->withProviders([...])
 *       ->withMiddleware([...])
 *       ->run();
 */
final class Application
{
    /** @var array<class-string<ServiceProviderInterface>> */
    private array $additionalProviders = [];

    /** @var array<class-string> */
    private array $additionalMiddleware = [];

    /** @var array<string, mixed> */
    private array $bindings = [];

    private ?Container $container = null;

    public readonly string $environment;

    public readonly bool $debug;

    private function __construct(
        public readonly string $basePath,
    ) {
        $this->environment = $_ENV['APP_ENV'] ?? 'production';
        $this->debug = filter_var($_ENV['APP_DEBUG'] ?? 'false', FILTER_VALIDATE_BOOLEAN);
    }

    public static function create(string $basePath): self
    {
        return new self(basePath: $basePath);
    }

    /**
     * @param array<class-string<ServiceProviderInterface>> $providers
     */
    public function withProviders(array $providers): self
    {
        $this->additionalProviders = array_merge($this->additionalProviders, $providers);
        return $this;
    }

    /**
     * Register additional middleware classes to prepend to the HTTP pipeline.
     *
     * These are stored and made available to the Kernel via the container
     * under the 'app.middleware' key so the pipeline can pick them up.
     *
     * @param array<class-string> $middleware
     */
    public function withMiddleware(array $middleware): self
    {
        $this->additionalMiddleware = array_merge($this->additionalMiddleware, $middleware);
        return $this;
    }

    /**
     * @param array<string, callable|object> $bindings
     */
    public function withBindings(array $bindings): self
    {
        $this->bindings = array_merge($this->bindings, $bindings);
        return $this;
    }

    public function run(): void
    {
        $container = $this->boot();

        if (PHP_SAPI === 'cli') {
            $this->runCli($container);
            return;
        }

        $this->runHttp($container);
    }

    public function boot(): Container
    {
        if ($this->container !== null) {
            return $this->container;
        }

        // ── Load MLC configuration ───────────────────────────────────
        $mlcConfig = ConfigLoader::loadMlc($this->basePath . '/config');

        // ── Base definitions (always present, cached or not) ─────────
        $baseDefinitions = [
            self::class              => fn(): self => $this,
            ContainerInterface::class => fn(Container $c): Container => $c,
            MlcConfig::class         => fn(): MlcConfig => $mlcConfig,
            'app.middleware'          => fn(): array => $this->additionalMiddleware,
        ];

        // ── Try compiled container cache (production only) ───────────
        $cachePath = $this->basePath . '/var/cache/container.compiled.php';
        $isProduction = $this->environment === 'production';

        if ($isProduction && CompiledContainerCache::exists($cachePath)) {
            $cached = CompiledContainerCache::load($cachePath);

            if ($cached !== null) {
                $this->container = (new ContainerBuilder())
                    ->addDefinitions($baseDefinitions)
                    ->addDefinitions($cached)
                    ->build();

                return $this->container;
            }
        }

        // ── Build fresh container ────────────────────────────────────
        $builder = new ContainerBuilder();
        $builder->addDefinitions($baseDefinitions);

        // User bindings
        if ($this->bindings !== []) {
            $builder->addDefinitions($this->bindings);
        }

        // Core providers + user providers via AppConfig
        $appConfig = new AppConfig();
        $context = PHP_SAPI === 'cli' ? 'cli' : 'http';
        $allDefinitions = $appConfig($context);
        $builder->addDefinitions($allDefinitions);

        // Scan for #[Provider] attributed providers in app/
        $appProvidersDir = $this->basePath . '/app/Providers';

        if (is_dir($appProvidersDir)) {
            $scanner = new ProviderScanner();
            $scannedClasses = $scanner->scan($appProvidersDir, 'App\\Providers');

            foreach ($scannedClasses as $className) {
                /** @var ServiceProviderInterface $provider */
                $provider = new $className();

                $providerContext = $provider->context();

                if ($providerContext !== 'all' && $providerContext !== $context) {
                    continue;
                }

                $builder->addDefinitions($provider->getDefinitions());
            }
        }

        // Additional runtime providers
        foreach ($this->additionalProviders as $providerClass) {
            /** @var ServiceProviderInterface $provider */
            $provider = new $providerClass();
            $builder->addDefinitions($provider->getDefinitions());
        }

        $this->container = $builder->build();

        // ── Compile cache for production ─────────────────────────────
        // Collects all scalar/array definitions that survived the
        // Closure/Object filter. The closures (service factories) are
        // re-provided on boot by the providers; what we cache here are
        // the resolved config values, flags, etc.
        if ($isProduction) {
            CompiledContainerCache::compile($cachePath, $allDefinitions + $this->bindings);
        }

        return $this->container;
    }

    public function getContainer(): Container
    {
        return $this->boot();
    }

    private function runHttp(Container $container): void
    {
        $kernel = new Kernel($container, $this);
        $kernel->handle();
    }

    private function runCli(Container $container): void
    {
        if (class_exists(\MonkeysLegion\Cli\CliKernel::class)) {
            /** @var \MonkeysLegion\Cli\CliKernel $kernel */
            $kernel = $container->get(\MonkeysLegion\Cli\CliKernel::class);

            $exitCode = $kernel->run($_SERVER['argv'] ?? []);
            exit($exitCode);
        }

        fwrite(STDERR, "MonkeysLegion CLI package not installed.\n");
        exit(1);
    }
}
