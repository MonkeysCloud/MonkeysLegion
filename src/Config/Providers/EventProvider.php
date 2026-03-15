<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Events\EventDispatcher;
use MonkeysLegion\Events\ListenerProvider;
use Psr\EventDispatcher\EventDispatcherInterface;

final class EventProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            ListenerProvider::class         => fn() => new ListenerProvider(),
            EventDispatcherInterface::class => fn($c) => new EventDispatcher(
                $c->get(ListenerProvider::class)
            ),
        ];
    }
}
