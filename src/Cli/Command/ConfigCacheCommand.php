<?php

declare(strict_types=1);

namespace MonkeysLegion\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\DI\CompiledContainerCache;

#[CommandAttr('config:cache', 'Compile and cache the container definitions for production')]
final class ConfigCacheCommand extends Command
{
    public function __construct()
    {
        parent::__construct();
    }

    protected function handle(): int
    {
        $cachePath = base_path('var/cache/container.php');

        $this->info('Compiling container definitions...');

        try {
            $config = new \MonkeysLegion\Config\AppConfig();
            $definitions = $config();

            CompiledContainerCache::compile($cachePath, $definitions);

            $count = count($definitions);
            $this->info("Container cached successfully ({$count} definitions).");
            $this->info("Cache file: {$cachePath}");

            return self::SUCCESS;
        } catch (\Throwable $e) {
            $this->error("Failed to cache container: {$e->getMessage()}");
            return self::FAILURE;
        }
    }
}
