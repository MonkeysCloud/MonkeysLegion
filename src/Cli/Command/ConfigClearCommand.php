<?php

declare(strict_types=1);

namespace MonkeysLegion\Cli\Command;

use MonkeysLegion\Cli\Console\Attributes\Command as CommandAttr;
use MonkeysLegion\Cli\Console\Command;
use MonkeysLegion\DI\CompiledContainerCache;

#[CommandAttr('config:clear', 'Clear the cached container definitions')]
final class ConfigClearCommand extends Command
{
    public function __construct()
    {
        parent::__construct();
    }

    protected function handle(): int
    {
        $cachePath = base_path('var/cache/container.php');

        if (!CompiledContainerCache::exists($cachePath)) {
            $this->info('No container cache to clear.');
            return self::SUCCESS;
        }

        if (CompiledContainerCache::clear($cachePath)) {
            $this->info('Container cache cleared successfully.');
            return self::SUCCESS;
        }

        $this->error("Failed to clear container cache at: {$cachePath}");
        return self::FAILURE;
    }
}
