<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Cache\CacheManagerBridge;
use MonkeysLegion\Database\Cache\Contracts\CacheInterface as DatabaseCacheInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Database\Factory\ConnectionFactory;
use MonkeysLegion\Database\MySQL\Connection;
use MonkeysLegion\Cache\CacheManager;
use MonkeysLegion\Entity\Scanner\EntityScanner;
use MonkeysLegion\Migration\MigrationGenerator;
use MonkeysLegion\Query\QueryBuilder;
use MonkeysLegion\Repository\RepositoryFactory;

final class DatabaseProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Database Connection */
            ConnectionInterface::class => function () {
                $path = base_path('config/database.php');
                if (file_exists($path)) {
                    $config = require $path;
                } else {
                    $config = [
                        'default' => 'sqlite',
                        'connections' => [
                            'sqlite' => [
                                'driver' => 'sqlite',
                                'database' => ':memory:',
                            ],
                        ],
                    ];
                }
                return ConnectionFactory::create($config);
            },

            Connection::class => fn($c) => $c->get(ConnectionInterface::class),

            /* Query Builder & Repositories */
            QueryBuilder::class => fn($c) => new QueryBuilder($c->get(ConnectionInterface::class)),

            RepositoryFactory::class => fn($c) => new RepositoryFactory(
                $c->get(QueryBuilder::class)
            ),

            /* Entity scanner + migration generator */
            EntityScanner::class      => fn() => new EntityScanner(),
            MigrationGenerator::class => fn($c) => new MigrationGenerator(
                $c->get(ConnectionInterface::class)
            ),

            /* Database Cache */
            DatabaseCacheInterface::class => function ($c) {
                $path = base_path('config/cache.php');
                $config = is_file($path) ? require $path : [];
                $manager = new CacheManager($config);
                return new CacheManagerBridge($manager, $config['prefix'] ?? '');
            },
        ];
    }
}
