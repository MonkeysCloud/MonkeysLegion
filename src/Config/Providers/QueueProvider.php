<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Queue\Batch\BatchRepository;
use MonkeysLegion\Queue\Contracts\QueueDispatcherInterface;
use MonkeysLegion\Queue\Contracts\QueueInterface;
use MonkeysLegion\Queue\Dashboard\DashboardController;
use MonkeysLegion\Queue\Dispatcher\QueueDispatcher;
use MonkeysLegion\Queue\Events\QueueEventDispatcher;
use MonkeysLegion\Queue\Factory\QueueFactory;
use MonkeysLegion\Queue\RateLimiter\RateLimiter;
use MonkeysLegion\Queue\RateLimiter\RateLimiterInterface;
use MonkeysLegion\Queue\Worker\Worker;

/**
 * Queue driver, dispatcher, batch repository, rate limiter, and worker provider.
 *
 * Updated for monkeyslegion-queue 2.0:
 *  - Worker now resolves optional deps (EventDispatcher, RateLimiter,
 *    BatchRepository, Logger) via ContainerAware — no constructor injection.
 *  - RateLimiterInterface is registered for optional per-queue throttling.
 *  - DashboardController is registered for the built-in queue dashboard.
 */
final class QueueProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            QueueFactory::class => static function ($c): QueueFactory {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new QueueFactory(
                    config: $mlc->getArray('queue', []) ?? [],
                    dbConnection: $c->get(ConnectionInterface::class),
                );
            },

            QueueInterface::class => fn($c): QueueInterface => $c->get(QueueFactory::class)->make(),

            BatchRepository::class => static function ($c): BatchRepository {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new BatchRepository(
                    connection: $c->get(ConnectionInterface::class),
                    table: $mlc->getString('queue.batch_table', 'job_batches') ?? 'job_batches',
                    queue: $c->get(QueueInterface::class),
                );
            },

            QueueEventDispatcher::class => fn(): QueueEventDispatcher => new QueueEventDispatcher(),

            /* Rate limiter — configurable via MLC */
            RateLimiterInterface::class => static function ($c): RateLimiter {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new RateLimiter(
                    maxAttempts: $mlc->getInt('queue.rate_limiter.max_attempts', 60) ?? 60,
                    decaySeconds: $mlc->getInt('queue.rate_limiter.decay_seconds', 60) ?? 60,
                );
            },

            QueueDispatcherInterface::class => fn($c): QueueDispatcher => new QueueDispatcher(
                queueDriver: $c->get(QueueInterface::class),
                batchRepository: $c->get(BatchRepository::class),
            ),

            /*
             * Worker — v2.0 uses ContainerAware to resolve optional deps
             * (QueueEventDispatcher, RateLimiterInterface, BatchRepository, Logger)
             * from the global DI container automatically.
             */
            Worker::class => static function ($c): Worker {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new Worker(
                    queue: $c->get(QueueInterface::class),
                    sleep: $mlc->getInt('queue.worker.sleep', 3) ?? 3,
                    maxTries: $mlc->getInt('queue.worker.max_tries', 3) ?? 3,
                    memory: $mlc->getInt('queue.worker.memory', 128) ?? 128,
                    timeout: $mlc->getInt('queue.worker.timeout', 60) ?? 60,
                    delayedCheckInterval: $mlc->getInt('queue.worker.delayed_check_interval', 30) ?? 30,
                );
            },

            /* Dashboard controller — v2.0 built-in queue dashboard */
            DashboardController::class => static function ($c): DashboardController {
                return new DashboardController(
                    queue: $c->get(QueueInterface::class),
                    renderer: $c->get(\MonkeysLegion\Template\Renderer::class),
                );
            },
        ];
    }
}
