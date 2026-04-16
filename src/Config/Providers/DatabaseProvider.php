<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Database\Connection\ConnectionManager;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Database\Contracts\ConnectionManagerInterface;
use MonkeysLegion\Entity\Scanner\EntityScanner;
use MonkeysLegion\Migration\MigrationGenerator;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Query\Query\QueryBuilder;

/**
 * Database connection manager, query builder, entity scanner, and migration.
 *
 * Uses ConnectionManager::fromArray() which handles DatabaseConfig/DsnConfig construction.
 */
final class DatabaseProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Connection Manager */
            ConnectionManagerInterface::class => static function ($c): ConnectionManagerInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $connections = $mlc->getArray('database.connections', []) ?? [];

                if ($connections === []) {
                    // Fallback to legacy config
                    $legacyPath = base_path('config/database.php');

                    if (is_file($legacyPath)) {
                        $legacyConfig = require $legacyPath;
                        $connections = $legacyConfig['connections'] ?? [];
                    }
                }

                if ($connections === []) {
                    // Build from env vars
                    $driver = $_ENV['DB_CONNECTION'] ?? 'mysql';

                    $connections[$driver] = [
                        'driver'   => $driver,
                        'host'     => $_ENV['DB_HOST'] ?? '127.0.0.1',
                        'port'     => (int) ($_ENV['DB_PORT'] ?? 3306),
                        'database' => $_ENV['DB_DATABASE'] ?? '',
                        'username' => $_ENV['DB_USERNAME'] ?? 'root',
                        'password' => $_ENV['DB_PASSWORD'] ?? '',
                        'charset'  => 'utf8mb4',
                    ];
                }

                return ConnectionManager::fromArray($connections);
            },

            ConnectionInterface::class => fn($c): ConnectionInterface
                => $c->get(ConnectionManagerInterface::class)->connection(),

            /* Query Builder — uses ConnectionManagerInterface, not ConnectionInterface */
            QueryBuilder::class => fn($c): QueryBuilder => new QueryBuilder(
                manager: $c->get(ConnectionManagerInterface::class),
            ),

            /* Entity Scanner */
            EntityScanner::class => fn(): EntityScanner => new EntityScanner(),

            /* Migration Generator */
            MigrationGenerator::class => fn($c): MigrationGenerator => new MigrationGenerator(
                $c->get(ConnectionInterface::class),
            ),
        ];
    }
}
