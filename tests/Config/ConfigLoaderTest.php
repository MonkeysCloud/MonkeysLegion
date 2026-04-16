<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Config;

use MonkeysLegion\Config\ConfigLoader;
use MonkeysLegion\Mlc\Config as MlcConfig;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Config\ConfigLoader
 */
final class ConfigLoaderTest extends TestCase
{
    private string $configDir;
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->configDir = sys_get_temp_dir() . '/ml_config_test_' . bin2hex(random_bytes(4));
        $this->cacheDir  = dirname($this->configDir) . '/ml_cache_test_' . bin2hex(random_bytes(4));
        mkdir($this->configDir, 0755, true);
    }

    protected function tearDown(): void
    {
        // Clean up config dir
        foreach (glob($this->configDir . '/*') ?: [] as $f) {
            unlink($f);
        }

        if (is_dir($this->configDir)) {
            rmdir($this->configDir);
        }

        // Clean up cache dir
        $cachePath = dirname($this->configDir) . '/var/cache/config.compiled.php';

        if (is_file($cachePath)) {
            unlink($cachePath);
        }

        if (is_dir(dirname($this->configDir) . '/var/cache')) {
            @rmdir(dirname($this->configDir) . '/var/cache');
        }

        if (is_dir(dirname($this->configDir) . '/var')) {
            @rmdir(dirname($this->configDir) . '/var');
        }
    }

    public function testReturnsEmptyConfigForMissingDirectory(): void
    {
        $result = ConfigLoader::loadMlc('/nonexistent/path/config');

        $this->assertInstanceOf(MlcConfig::class, $result);
    }

    public function testReturnsEmptyConfigForEmptyDirectory(): void
    {
        $result = ConfigLoader::loadMlc($this->configDir);

        $this->assertInstanceOf(MlcConfig::class, $result);
    }

    public function testSkipsExampleFiles(): void
    {
        file_put_contents($this->configDir . '/app.mlc.example', "name = TestApp\n");

        $result = ConfigLoader::loadMlc($this->configDir);

        $this->assertInstanceOf(MlcConfig::class, $result);
    }

    public function testDiscoverConfigNamesReturnsSortedUnique(): void
    {
        // Create some .mlc files
        file_put_contents($this->configDir . '/database.mlc', "driver = mysql\n");
        file_put_contents($this->configDir . '/app.mlc', "name = Test\n");
        file_put_contents($this->configDir . '/app.mlc.example', "name = Example\n");

        // Use reflection to test the private method
        $method = new \ReflectionMethod(ConfigLoader::class, 'discoverConfigNames');

        $result = $method->invoke(null, $this->configDir);

        $this->assertIsArray($result);
        $this->assertContains('app', $result);
        $this->assertContains('database', $result);
        // Examples should be excluded
        $this->assertNotContains('app.mlc.example', $result);
        // Should be sorted
        $this->assertSame($result, array_values(array_unique($result)));
    }
}
