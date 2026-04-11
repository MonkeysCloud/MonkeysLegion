<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Provider;

use MonkeysLegion\Core\Attributes\Provider;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;

final class ProviderScanner
{
    /**
     * @param string $directory Absolute directory to scan
     * @param string $namespace Prefix namespace for that directory
     * @return string[] Fully-qualified class names with #[Provider]
     */
    public function scan(string $directory, string $namespace = 'App\\Providers'): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $classes = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if (!$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            // Build the fully-qualified class name
            $relativePath = substr($file->getRealPath(), strlen($directory) + 1);
            $className = $namespace . '\\' . strtr($relativePath, ['/' => '\\', '.php' => '']);

            if (!class_exists($className)) {
                continue;
            }

            $reflection = new ReflectionClass($className);
            if ($reflection->isAbstract()) {
                continue;
            }

            $attributes = $reflection->getAttributes(Provider::class);
            if (!empty($attributes)) {
                $classes[] = $className;
            }
        }

        return $classes;
    }
}
