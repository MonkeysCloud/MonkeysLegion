<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cli\CliKernel;
use MonkeysLegion\Cli\Support\CommandFinder;

/**
 * CLI kernel and command registration provider.
 *
 * CLI-only context. Uses CliKernel which auto-discovers vendor + app commands.
 */
final class CliProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'cli';
    }

    public function getDefinitions(): array
    {
        return [
            CliKernel::class => function($c): CliKernel {
                // 1. Discovery via CommandFinder (Composer PSR-4)
                $discovered = CommandFinder::all();

                return new CliKernel(
                    container: $c,
                    commands: [...$discovered],
                );
            },
        ];
    }
}
