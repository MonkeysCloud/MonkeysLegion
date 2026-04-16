<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Provider;

use MonkeysLegion\Config\Providers\ServiceProviderInterface;
use MonkeysLegion\Framework\Attributes\BootAfter;
use MonkeysLegion\Framework\Attributes\Provider;

/**
 * Scans directories for classes annotated with #[Provider] and returns
 * them sorted by priority and then topologically by #[BootAfter] dependencies.
 */
final class ProviderScanner
{
    /**
     * Scan a directory for #[Provider] attributed classes.
     *
     * @param string $directory Absolute path to scan
     * @param string $namespace PSR-4 namespace prefix for the directory
     * @return array<class-string<ServiceProviderInterface>> Sorted provider class names
     */
    public function scan(string $directory, string $namespace): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $providers   = [];
        $iterator    = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $relativePath = str_replace(
                [$directory . DIRECTORY_SEPARATOR, DIRECTORY_SEPARATOR, '.php'],
                ['', '\\', ''],
                $file->getPathname(),
            );

            $className = $namespace . '\\' . $relativePath;

            if (!class_exists($className)) {
                continue;
            }

            $reflection = new \ReflectionClass($className);

            // Must implement ServiceProviderInterface
            if (!$reflection->implementsInterface(ServiceProviderInterface::class)) {
                continue;
            }

            // Must have #[Provider] attribute
            $attrs = $reflection->getAttributes(Provider::class);

            if ($attrs === []) {
                continue;
            }

            /** @var Provider $providerAttr */
            $providerAttr = $attrs[0]->newInstance();

            // Collect #[BootAfter] dependencies
            $bootAfterAttrs = $reflection->getAttributes(BootAfter::class);
            $dependencies    = array_map(
                static fn(\ReflectionAttribute $attr): string => $attr->newInstance()->dependency,
                $bootAfterAttrs,
            );

            $providers[] = [
                'class'        => $className,
                'priority'     => $providerAttr->priority,
                'context'      => $providerAttr->context,
                'dependencies' => $dependencies,
            ];
        }

        // Sort by priority (higher first)
        usort($providers, static function (array $a, array $b): int {
            return $b['priority'] <=> $a['priority'];
        });

        // Topological sort by #[BootAfter] dependencies
        return $this->topologicalSort($providers);
    }

    /**
     * Perform a stable topological sort using Kahn's algorithm.
     *
     * Providers without dependencies or whose dependencies are not in
     * the scanned set are placed first (in their priority order).
     *
     * @param array<array{class: string, priority: int, context: string, dependencies: list<string>}> $providers
     * @return array<class-string<ServiceProviderInterface>>
     */
    private function topologicalSort(array $providers): array
    {
        if (count($providers) <= 1) {
            return array_column($providers, 'class');
        }

        // Build adjacency: class → index, and in-degree counts
        $indexMap = [];

        foreach ($providers as $i => $p) {
            $indexMap[$p['class']] = $i;
        }

        /** @var array<int, int> $inDegree */
        $inDegree = array_fill(0, count($providers), 0);

        /** @var array<int, list<int>> $edges  dependency → [dependents] */
        $edges = array_fill(0, count($providers), []);

        foreach ($providers as $i => $p) {
            foreach ($p['dependencies'] as $dep) {
                if (!isset($indexMap[$dep])) {
                    continue; // Dependency not in scanned set — already loaded
                }

                $depIdx = $indexMap[$dep];
                $edges[$depIdx][] = $i;
                $inDegree[$i]++;
            }
        }

        // Seed queue with zero-in-degree nodes (preserving priority order)
        $queue = [];

        foreach ($inDegree as $i => $deg) {
            if ($deg === 0) {
                $queue[] = $i;
            }
        }

        $sorted = [];

        while ($queue !== []) {
            $idx = array_shift($queue);
            $sorted[] = $providers[$idx]['class'];

            foreach ($edges[$idx] as $dependent) {
                $inDegree[$dependent]--;

                if ($inDegree[$dependent] === 0) {
                    $queue[] = $dependent;
                }
            }
        }

        // If cycle detected, append remaining providers unsorted
        if (count($sorted) < count($providers)) {
            foreach ($providers as $p) {
                if (!in_array($p['class'], $sorted, true)) {
                    $sorted[] = $p['class'];
                }
            }
        }

        return $sorted;
    }
}
