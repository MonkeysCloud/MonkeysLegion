<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DI;

use MonkeysLegion\DI\CompiledContainerCache;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DI\CompiledContainerCache
 */
final class CompiledContainerCacheTest extends TestCase
{
    private string $cacheDir;

    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir() . '/ml_test_cache_' . bin2hex(random_bytes(4));
        mkdir($this->cacheDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->recursiveDelete($this->cacheDir);
    }

    private function recursiveDelete(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        ) as $item) {
            /** @var \SplFileInfo $item */
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir($dir);
    }

    public function testExistsReturnsFalseForMissingFile(): void
    {
        $this->assertFalse(CompiledContainerCache::exists($this->cacheDir . '/nope.php'));
    }

    public function testExistsReturnsTrueForExistingFile(): void
    {
        $path = $this->cacheDir . '/exists.php';
        file_put_contents($path, '<?php return [];');

        $this->assertTrue(CompiledContainerCache::exists($path));
    }

    public function testLoadReturnsNullForMissingFile(): void
    {
        $this->assertNull(CompiledContainerCache::load($this->cacheDir . '/missing.php'));
    }

    public function testLoadReturnsArrayFromValidCache(): void
    {
        $path = $this->cacheDir . '/valid.php';
        file_put_contents($path, '<?php return ["foo" => "bar"];');

        $result = CompiledContainerCache::load($path);

        $this->assertIsArray($result);
        $this->assertSame(['foo' => 'bar'], $result);
    }

    public function testLoadReturnsNullForNonArrayReturn(): void
    {
        $path = $this->cacheDir . '/string.php';
        file_put_contents($path, '<?php return "not an array";');

        $this->assertNull(CompiledContainerCache::load($path));
    }

    public function testLoadReturnsNullForInvalidPhp(): void
    {
        $path = $this->cacheDir . '/broken.php';
        file_put_contents($path, '<?php throw new \RuntimeException("boom");');

        $this->assertNull(CompiledContainerCache::load($path));
    }

    public function testCompileWritesCacheableDefinitions(): void
    {
        $path = $this->cacheDir . '/compiled.php';

        $definitions = [
            'app.name'    => 'MonkeysLegion',
            'app.version' => '2.0.0',
            'debug'       => true,
        ];

        CompiledContainerCache::compile($path, $definitions);

        $this->assertFileExists($path);

        $loaded = require $path;
        $this->assertIsArray($loaded);
        $this->assertSame('MonkeysLegion', $loaded['app.name']);
        $this->assertSame('2.0.0', $loaded['app.version']);
        $this->assertTrue($loaded['debug']);
    }

    public function testCompileSkipsClosures(): void
    {
        $path = $this->cacheDir . '/no_closures.php';

        $definitions = [
            'scalar'  => 42,
            'closure' => fn(): string => 'hello',
            'objects' => new \stdClass(),
        ];

        CompiledContainerCache::compile($path, $definitions);

        $this->assertFileExists($path);

        $loaded = require $path;
        $this->assertArrayHasKey('scalar', $loaded);
        $this->assertArrayNotHasKey('closure', $loaded);
        $this->assertArrayNotHasKey('objects', $loaded);
    }

    public function testCompileSkipsEmptyDefinitions(): void
    {
        $path = $this->cacheDir . '/empty.php';

        // All closures = nothing cacheable
        CompiledContainerCache::compile($path, [
            'a' => fn(): int => 1,
            'b' => fn(): int => 2,
        ]);

        $this->assertFileDoesNotExist($path);
    }

    public function testCompileCreatesDirectoryIfMissing(): void
    {
        $nestedDir = $this->cacheDir . '/deep/nested';
        $path = $nestedDir . '/compiled.php';

        CompiledContainerCache::compile($path, ['key' => 'value']);

        $this->assertFileExists($path);
    }

    public function testClearRemovesFile(): void
    {
        $path = $this->cacheDir . '/to_clear.php';
        file_put_contents($path, '<?php return [];');

        $this->assertFileExists($path);

        CompiledContainerCache::clear($path);

        $this->assertFileDoesNotExist($path);
    }

    public function testClearDoesNothingForMissingFile(): void
    {
        // Should not throw
        CompiledContainerCache::clear($this->cacheDir . '/nonexistent.php');
        $this->assertTrue(true);
    }

    public function testIsValidReturnsTrueForValidCache(): void
    {
        $path = $this->cacheDir . '/valid_check.php';
        file_put_contents($path, '<?php return ["key" => "val"];');

        $this->assertTrue(CompiledContainerCache::isValid($path));
    }

    public function testIsValidReturnsFalseForEmptyCache(): void
    {
        $path = $this->cacheDir . '/empty_check.php';
        file_put_contents($path, '<?php return [];');

        $this->assertFalse(CompiledContainerCache::isValid($path));
    }

    public function testIsValidReturnsFalseForMissingFile(): void
    {
        $this->assertFalse(CompiledContainerCache::isValid($this->cacheDir . '/nope.php'));
    }
}
