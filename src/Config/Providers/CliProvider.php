<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cli\CliKernel;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Container\ContainerInterface;

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
            CliKernel::class => fn($c): CliKernel => new CliKernel(
                container: $c,
            ),
        ];
    }
}
