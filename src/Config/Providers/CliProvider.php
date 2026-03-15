<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cli\CliKernel;
use MonkeysLegion\Cli\Support\CommandFinder;

final class CliProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'cli';
    }

    public function getDefinitions(): array
    {
        return [
            CliKernel::class => fn($c) => new CliKernel(
                $c,
                CommandFinder::all()
            ),
        ];
    }
}
