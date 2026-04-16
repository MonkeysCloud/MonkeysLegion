<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Framework\Application;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\Application
 */
final class ApplicationTest extends TestCase
{
    private string $basePath;

    protected function setUp(): void
    {
        $this->basePath = sys_get_temp_dir() . '/ml_app_test_' . bin2hex(random_bytes(4));
        mkdir($this->basePath . '/config', 0755, true);

        $_ENV['APP_ENV']   = 'testing';
        $_ENV['APP_DEBUG'] = 'true';
    }

    protected function tearDown(): void
    {
        // Clean up
        foreach (glob($this->basePath . '/config/*') ?: [] as $f) {
            unlink($f);
        }

        @rmdir($this->basePath . '/config');

        $cacheDir = $this->basePath . '/var/cache';

        if (is_dir($cacheDir)) {
            foreach (glob($cacheDir . '/*') ?: [] as $f) {
                unlink($f);
            }

            @rmdir($cacheDir);
            @rmdir($this->basePath . '/var');
        }

        @rmdir($this->basePath);
    }

    public function testCreateReturnsApplication(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $this->assertInstanceOf(Application::class, $app);
    }

    public function testBasePathIsStored(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $this->assertSame($this->basePath, $app->basePath);
    }

    public function testEnvironmentIsReadFromEnv(): void
    {
        $_ENV['APP_ENV'] = 'staging';

        $app = Application::create(basePath: $this->basePath);

        $this->assertSame('staging', $app->environment);

        $_ENV['APP_ENV'] = 'testing';
    }

    public function testDebugIsReadFromEnv(): void
    {
        $_ENV['APP_DEBUG'] = 'true';

        $app = Application::create(basePath: $this->basePath);

        $this->assertTrue($app->debug);
    }

    public function testDebugDefaultsToFalse(): void
    {
        unset($_ENV['APP_DEBUG']);

        $app = Application::create(basePath: $this->basePath);

        $this->assertFalse($app->debug);

        $_ENV['APP_DEBUG'] = 'true';
    }

    public function testWithProvidersReturnsSelf(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $result = $app->withProviders([]);

        $this->assertSame($app, $result);
    }

    public function testWithMiddlewareReturnsSelf(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $result = $app->withMiddleware([]);

        $this->assertSame($app, $result);
    }

    public function testWithBindingsReturnsSelf(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $result = $app->withBindings([]);

        $this->assertSame($app, $result);
    }

    public function testBootReturnsContainer(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $container = $app->boot();

        $this->assertInstanceOf(Container::class, $container);
    }

    public function testBootReturnsSameContainerOnSecondCall(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $c1 = $app->boot();
        $c2 = $app->boot();

        $this->assertSame($c1, $c2);
    }

    public function testGetContainerCallsBoot(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $container = $app->getContainer();

        $this->assertInstanceOf(Container::class, $container);
    }

    public function testContainerHasSelfReference(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $container = $app->boot();

        $this->assertTrue($container->has(Application::class));
        $this->assertSame($app, $container->get(Application::class));
    }

    public function testContainerHasMlcConfig(): void
    {
        $app = Application::create(basePath: $this->basePath);

        $container = $app->boot();

        $this->assertTrue($container->has(\MonkeysLegion\Mlc\Config::class));
    }

    public function testWithBindingsRegistersCustomDefinitions(): void
    {
        $app = Application::create(basePath: $this->basePath)
            ->withBindings([
                'test.value' => fn(): string => 'hello_world',
            ]);

        $container = $app->boot();

        $this->assertTrue($container->has('test.value'));
        $this->assertSame('hello_world', $container->get('test.value'));
    }
}
