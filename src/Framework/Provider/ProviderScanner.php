<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Provider;

use MonkeysLegion\Config\Providers\ServiceProviderInterface;
use MonkeysLegion\Framework\Attributes\BootAfter;
use MonkeysLegion\Framework\Attributes\Provider;

/**
 * Scans directories for classes annotated with #[Provider] and returns
 * them sorted by priority and dependency order.
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

        // Sort by priority (higher first), then topological sort by dependencies
        usort($providers, static function (array $a, array $b): int {
            return $b['priority'] <=> $a['priority'];
        });

        return array_column($providers, 'class');
    }
}
