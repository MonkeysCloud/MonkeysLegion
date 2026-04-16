<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Queue\Batch\BatchRepository;
use MonkeysLegion\Queue\Contracts\QueueDispatcherInterface;
use MonkeysLegion\Queue\Contracts\QueueInterface;
use MonkeysLegion\Queue\Dispatcher\QueueDispatcher;
use MonkeysLegion\Queue\Events\QueueEventDispatcher;
use MonkeysLegion\Queue\Factory\QueueFactory;
use MonkeysLegion\Queue\Worker\Worker;

/**
 * Queue driver, dispatcher, batch repository, and worker provider.
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
                );
            },

            QueueEventDispatcher::class => fn(): QueueEventDispatcher => new QueueEventDispatcher(),

            QueueDispatcherInterface::class => fn($c): QueueDispatcher => new QueueDispatcher(
                queueDriver: $c->get(QueueInterface::class),
                batchRepository: $c->get(BatchRepository::class),
            ),

            /* Worker — uses simple constructor, resolves extras internally */
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
        ];
    }
}
