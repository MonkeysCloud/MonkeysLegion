<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Events\EventDispatcher;
use MonkeysLegion\Events\ListenerProvider;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * PSR-14 event dispatcher and listener provider.
 *
 * Uses the Events package's EventDispatcher with ListenerProvider.
 */
final class EventProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            ListenerProvider::class => fn(): ListenerProvider => new ListenerProvider(),

            EventDispatcher::class => fn($c): EventDispatcher => new EventDispatcher(
                provider: $c->get(ListenerProvider::class),
            ),

            EventDispatcherInterface::class => fn($c): EventDispatcher => $c->get(EventDispatcher::class),
        ];
    }
}
