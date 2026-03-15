<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Logger\Contracts\MonkeysLoggerInterface;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Queue\Batch\BatchRepository;
use MonkeysLegion\Queue\Contracts\QueueDispatcherInterface;
use MonkeysLegion\Queue\Contracts\QueueInterface;
use MonkeysLegion\Queue\Dispatcher\QueueDispatcher;
use MonkeysLegion\Queue\Events\QueueEventDispatcher;
use MonkeysLegion\Queue\Factory\QueueFactory;
use MonkeysLegion\Queue\Worker\Worker;
use MonkeysLegion\Schedule\Contracts\ScheduleDriver;
use MonkeysLegion\Schedule\Discovery\AttributeScanner;
use MonkeysLegion\Schedule\Driver\DriverFactory as ScheduleDriverFactory;
use MonkeysLegion\Schedule\Schedule;
use MonkeysLegion\Schedule\ScheduleManager;
use MonkeysLegion\Schedule\Support\CronParser;

final class QueueProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Queue Factory & Driver */
            QueueFactory::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new QueueFactory(
                    config: $mlc->get('queue', []),
                    dbConnection: $c->get(ConnectionInterface::class)
                );
            },

            QueueInterface::class => fn($c) => $c->get(QueueFactory::class)->make(),

            /* Batch Repository */
            BatchRepository::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return new BatchRepository(
                    connection: $c->get(ConnectionInterface::class),
                    table: $mlc->get('queue.batch_table', 'job_batches')
                );
            },

            QueueEventDispatcher::class => fn() => new QueueEventDispatcher(),

            /* Queue Dispatcher */
            QueueDispatcherInterface::class => static function ($c) {
                return new QueueDispatcher(
                    queueDriver: $c->get(QueueInterface::class),
                    batchRepository: $c->get(BatchRepository::class)
                );
            },

            QueueDispatcher::class => fn($c) => $c->get(QueueDispatcherInterface::class),

            /* Worker */
            Worker::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->get('queue.worker', []);

                return new Worker(
                    queue: $c->get(QueueInterface::class),
                    sleep: (int) ($config['sleep'] ?? 3),
                    maxTries: (int) ($config['max_tries'] ?? 3),
                    memory: (int) ($config['memory'] ?? 128),
                    timeout: (int) ($config['timeout'] ?? 60),
                    delayedCheckInterval: (int) ($config['delayed_check_interval'] ?? 30),
                    eventDispatcher: $c->get(QueueEventDispatcher::class),
                    batchRepository: $c->get(BatchRepository::class)
                );
            },

            /* Schedule */
            ScheduleDriver::class => static function ($c) {
                $factory = new ScheduleDriverFactory(
                    $c->get(\MonkeysLegion\Database\Cache\Contracts\CacheInterface::class),
                    $c->get(\Redis::class)
                );
                $driver = $_ENV['SCHEDULE_DRIVER'] ?? 'cache';
                return $factory->make($driver);
            },

            ScheduleManager::class => static function ($c) {
                $cacheInterface = $c->get(\MonkeysLegion\Database\Cache\Contracts\CacheInterface::class);
                $scanner = new AttributeScanner();
                $debug = (bool) $c->get(MlcConfig::class)->get('app.debug', false);
                return new ScheduleManager(
                    driver: $c->get(ScheduleDriver::class),
                    cache: $cacheInterface,
                    scanner: $scanner,
                    logger: $c->get(MonkeysLoggerInterface::class),
                    debugMode: $debug
                );
            },

            Schedule::class => fn($c) => new Schedule(
                manager: $c->get(ScheduleManager::class)
            ),

            CronParser::class => fn() => new CronParser(),
        ];
    }
}
