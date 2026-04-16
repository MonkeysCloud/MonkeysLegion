<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Config\Providers;

use MonkeysLegion\Config\Providers\AbstractServiceProvider;
use MonkeysLegion\Config\Providers\ApexProvider;
use MonkeysLegion\Config\Providers\AuthProvider;
use MonkeysLegion\Config\Providers\CacheProvider;
use MonkeysLegion\Config\Providers\CliProvider;
use MonkeysLegion\Config\Providers\DatabaseProvider;
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
use MonkeysLegion\Config\Providers\TelemetryProvider;
use MonkeysLegion\Config\Providers\TemplateProvider;
use MonkeysLegion\Config\Providers\ValidationProvider;
use MonkeysLegion\DI\Container;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Config\Providers\AbstractServiceProvider
 * @covers \MonkeysLegion\Config\Providers\HttpFactoryProvider
 * @covers \MonkeysLegion\Config\Providers\EventProvider
 * @covers \MonkeysLegion\Config\Providers\LoggerProvider
 * @covers \MonkeysLegion\Config\Providers\CacheProvider
 * @covers \MonkeysLegion\Config\Providers\DatabaseProvider
 * @covers \MonkeysLegion\Config\Providers\AuthProvider
 * @covers \MonkeysLegion\Config\Providers\I18nProvider
 * @covers \MonkeysLegion\Config\Providers\ValidationProvider
 * @covers \MonkeysLegion\Config\Providers\QueueProvider
 * @covers \MonkeysLegion\Config\Providers\FilesProvider
 * @covers \MonkeysLegion\Config\Providers\TelemetryProvider
 * @covers \MonkeysLegion\Config\Providers\ApexProvider
 * @covers \MonkeysLegion\Config\Providers\RoutingProvider
 * @covers \MonkeysLegion\Config\Providers\SessionProvider
 * @covers \MonkeysLegion\Config\Providers\MiddlewareProvider
 * @covers \MonkeysLegion\Config\Providers\TemplateProvider
 * @covers \MonkeysLegion\Config\Providers\OpenApiProvider
 * @covers \MonkeysLegion\Config\Providers\CliProvider
 * @covers \MonkeysLegion\Config\Providers\ScheduleProvider
 */
final class ProviderDefinitionsTest extends TestCase
{
    // ── AbstractServiceProvider defaults ─────────────────────────

    public function testAbstractServiceProviderDefaults(): void
    {
        $provider = new class extends AbstractServiceProvider {
            public function getDefinitions(): array
            {
                return ['TestService' => fn(): string => 'hello'];
            }
        };

        $this->assertSame('all', $provider->context());
        $this->assertFalse($provider->isDeferred());
        $this->assertSame(['TestService'], $provider->provides());
    }

    public function testAbstractServiceProviderBootIsNoOp(): void
    {
        $provider = new class extends AbstractServiceProvider {
            public function getDefinitions(): array
            {
                return [];
            }
        };

        // boot() should not throw
        $container = $this->createMock(Container::class);
        $provider->boot($container);

        $this->assertTrue(true);
    }

    // ── Context filtering ───────────────────────────────────────

    /**
     * @dataProvider httpOnlyProviders
     */
    public function testHttpOnlyProvidersReturnHttpContext(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        $this->assertSame('http', $provider->context());
    }

    public static function httpOnlyProviders(): iterable
    {
        yield 'Routing'      => [RoutingProvider::class];
        yield 'Session'      => [SessionProvider::class];
        yield 'Middleware'    => [MiddlewareProvider::class];
        yield 'Template'     => [TemplateProvider::class];
        yield 'OpenApi'      => [OpenApiProvider::class];
    }

    /**
     * @dataProvider cliOnlyProviders
     */
    public function testCliOnlyProvidersReturnCliContext(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        $this->assertSame('cli', $provider->context());
    }

    public static function cliOnlyProviders(): iterable
    {
        yield 'Cli'      => [CliProvider::class];
        yield 'Schedule' => [ScheduleProvider::class];
    }

    /**
     * @dataProvider universalProviders
     */
    public function testUniversalProvidersReturnAllContext(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        $this->assertSame('all', $provider->context());
    }

    public static function universalProviders(): iterable
    {
        yield 'Logger'      => [LoggerProvider::class];
        yield 'Event'       => [EventProvider::class];
        yield 'Cache'       => [CacheProvider::class];
        yield 'Database'    => [DatabaseProvider::class];
        yield 'Validation'  => [ValidationProvider::class];
        yield 'I18n'        => [I18nProvider::class];
        yield 'Queue'       => [QueueProvider::class];
        yield 'Files'       => [FilesProvider::class];
        yield 'Telemetry'   => [TelemetryProvider::class];
        yield 'Apex'        => [ApexProvider::class];
        yield 'Auth'        => [AuthProvider::class];
        yield 'HttpFactory'  => [HttpFactoryProvider::class];
    }

    // ── Definitions are non-empty arrays ────────────────────────

    /**
     * @dataProvider allProviders
     */
    public function testAllProvidersReturnNonEmptyDefinitions(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        $definitions = $provider->getDefinitions();

        $this->assertIsArray($definitions);
        $this->assertNotEmpty($definitions, "{$providerClass} should return at least one definition.");
    }

    public static function allProviders(): iterable
    {
        yield 'HttpFactory'  => [HttpFactoryProvider::class];
        yield 'Routing'      => [RoutingProvider::class];
        yield 'Session'      => [SessionProvider::class];
        yield 'Middleware'    => [MiddlewareProvider::class];
        yield 'Template'     => [TemplateProvider::class];
        yield 'OpenApi'      => [OpenApiProvider::class];
        yield 'Cli'          => [CliProvider::class];
        yield 'Schedule'     => [ScheduleProvider::class];
        yield 'Logger'       => [LoggerProvider::class];
        yield 'Event'        => [EventProvider::class];
        yield 'Cache'        => [CacheProvider::class];
        yield 'Database'     => [DatabaseProvider::class];
        yield 'Validation'   => [ValidationProvider::class];
        yield 'I18n'         => [I18nProvider::class];
        yield 'Queue'        => [QueueProvider::class];
        yield 'Files'        => [FilesProvider::class];
        yield 'Telemetry'    => [TelemetryProvider::class];
        yield 'Apex'         => [ApexProvider::class];
        yield 'Auth'         => [AuthProvider::class];
    }

    // ── Definitions contain callable or object values ────────────

    /**
     * @dataProvider allProviders
     */
    public function testDefinitionValuesAreCallable(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        foreach ($provider->getDefinitions() as $id => $definition) {
            $this->assertTrue(
                is_callable($definition) || is_object($definition),
                "{$providerClass}: definition for '{$id}' is neither callable nor object.",
            );
        }
    }

    // ── provides() matches definition keys ──────────────────────

    /**
     * @dataProvider allProviders
     */
    public function testProvidesMatchesDefinitionKeys(string $providerClass): void
    {
        /** @var ServiceProviderInterface $provider */
        $provider = new $providerClass();

        $keys     = array_keys($provider->getDefinitions());
        $provides = $provider->provides();

        sort($keys);
        sort($provides);

        $this->assertSame($keys, $provides, "{$providerClass}: provides() mismatch");
    }

    // ── Specific providers register expected service IDs ─────────

    public function testEventProviderRegistersDispatcher(): void
    {
        $provider = new EventProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Events\ListenerProvider::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Events\EventDispatcher::class, $definitions);
        $this->assertArrayHasKey(\Psr\EventDispatcher\EventDispatcherInterface::class, $definitions);
    }

    public function testValidationProviderRegistersValidatorAndBinder(): void
    {
        $provider = new ValidationProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Validation\Validator::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Validation\DtoBinder::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Validation\Contracts\ValidatorInterface::class, $definitions);
    }

    public function testHttpFactoryRegistersPsrInterfaces(): void
    {
        $provider = new HttpFactoryProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\Psr\Http\Message\ResponseFactoryInterface::class, $definitions);
        $this->assertArrayHasKey(\Psr\Http\Message\StreamFactoryInterface::class, $definitions);
        $this->assertArrayHasKey(\Psr\Http\Message\ServerRequestInterface::class, $definitions);
    }

    public function testRoutingProviderRegistersRouterAndScanner(): void
    {
        $provider = new RoutingProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Router\Router::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Router\RouteCollection::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Router\UrlGenerator::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Router\ControllerScanner::class, $definitions);
    }

    public function testLoggerProviderRegistersPsr3Interface(): void
    {
        $provider = new LoggerProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\Psr\Log\LoggerInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Logger\Logger::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Logger\LogManager::class, $definitions);
    }

    public function testDatabaseProviderRegistersConnectionManager(): void
    {
        $provider = new DatabaseProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Database\Contracts\ConnectionManagerInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Database\Contracts\ConnectionInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Query\Query\QueryBuilder::class, $definitions);
    }

    public function testAuthProviderRegistersAuthManager(): void
    {
        $provider = new AuthProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Auth\Guard\AuthManager::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Auth\Service\AuthService::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Auth\Service\JwtService::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Auth\Service\PasswordHasher::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Auth\Middleware\AuthenticationMiddleware::class, $definitions);
    }

    public function testMiddlewareProviderRegistersCorePipeline(): void
    {
        $provider = new MiddlewareProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Http\CoreRequestHandler::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Http\MiddlewareDispatcher::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Http\Middleware\SecurityHeadersMiddleware::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Http\Middleware\CorsMiddleware::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Http\Middleware\RateLimitMiddleware::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Http\Emitter\SapiEmitter::class, $definitions);
    }

    public function testApexProviderRegistersAIFacade(): void
    {
        $provider = new ApexProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Apex\AI::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Apex\Contract\ProviderInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Apex\Cost\CostTracker::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Apex\Cost\PricingRegistry::class, $definitions);
    }

    public function testCacheProviderRegistersSimpleCacheInterface(): void
    {
        $provider = new CacheProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\Psr\SimpleCache\CacheInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Cache\CacheStoreInterface::class, $definitions);
        $this->assertArrayHasKey(\Redis::class, $definitions);
    }

    public function testTelemetryProviderRegistersTracerAndMetrics(): void
    {
        $provider = new TelemetryProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Telemetry\Tracing\TracerInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Telemetry\Metrics\MetricsInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Telemetry\Middleware\RequestMetricsMiddleware::class, $definitions);
    }

    public function testI18nProviderRegistersTranslator(): void
    {
        $provider = new I18nProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\I18n\Translator::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\I18n\LocaleManager::class, $definitions);
    }

    public function testQueueProviderRegistersDispatcher(): void
    {
        $provider = new QueueProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Queue\Factory\QueueFactory::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Queue\Contracts\QueueInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Queue\Worker\Worker::class, $definitions);
    }

    public function testFilesProviderRegistersStorageInterface(): void
    {
        $provider = new FilesProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Files\Contracts\StorageInterface::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Files\FilesManager::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Files\Image\ImageProcessor::class, $definitions);
    }

    public function testOpenApiProviderRegistersGenerator(): void
    {
        $provider = new OpenApiProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\OpenApi\OpenApiGenerator::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\OpenApi\OpenApiMiddleware::class, $definitions);
    }

    public function testSessionProviderRegistersManager(): void
    {
        $provider = new SessionProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Session\SessionManager::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Session\Middleware\SessionMiddleware::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Session\Middleware\VerifyCsrfToken::class, $definitions);
    }

    public function testTemplateProviderRegistersRenderer(): void
    {
        $provider = new TemplateProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Template\Renderer::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Template\Parser::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Template\Loader::class, $definitions);
    }

    public function testScheduleProviderRegistersSchedule(): void
    {
        $provider = new ScheduleProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Schedule\Schedule::class, $definitions);
        $this->assertArrayHasKey(\MonkeysLegion\Schedule\ScheduleManager::class, $definitions);
    }

    public function testCliProviderRegistersKernel(): void
    {
        $provider = new CliProvider();
        $definitions = $provider->getDefinitions();

        $this->assertArrayHasKey(\MonkeysLegion\Cli\CliKernel::class, $definitions);
    }
}
