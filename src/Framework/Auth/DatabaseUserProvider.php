<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Auth;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;

/**
 * Database-backed user provider for authentication.
 *
 * Implements all methods required by UserProviderInterface,
 * resolving users from a configurable database table.
 */
final class DatabaseUserProvider implements UserProviderInterface
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly string $table = 'users',
        private readonly string $modelClass = 'App\\Entity\\User',
    ) {}

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        return $this->fetchOne("SELECT * FROM {$this->table} WHERE id = :id LIMIT 1", ['id' => $id]);
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        return $this->fetchOne("SELECT * FROM {$this->table} WHERE email = :email LIMIT 1", ['email' => $email]);
    }

    public function findByRememberToken(int|string $id, string $token): ?AuthenticatableInterface
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table} WHERE id = :id AND remember_token = :token LIMIT 1",
            ['id' => $id, 'token' => $token],
        );
    }

    public function findByApiKey(string $key): ?AuthenticatableInterface
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table} WHERE api_key = :key LIMIT 1",
            ['key' => $key],
        );
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        $pdo = $this->connection->pdo();

        $columns = implode(', ', array_keys($attributes));
        $placeholders = implode(', ', array_map(fn(string $k): string => ":{$k}", array_keys($attributes)));

        $stmt = $pdo->prepare("INSERT INTO {$this->table} ({$columns}) VALUES ({$placeholders})");
        $stmt->execute($attributes);

        $id = $pdo->lastInsertId();

        return $this->findById($id) ?? throw new \RuntimeException('User not found after creation.');
    }

    public function updatePassword(int|string $id, string $hashedPassword): void
    {
        $pdo = $this->connection->pdo();
        $stmt = $pdo->prepare("UPDATE {$this->table} SET password = :password WHERE id = :id");
        $stmt->execute(['password' => $hashedPassword, 'id' => $id]);
    }

    public function incrementTokenVersion(int|string $id): void
    {
        $pdo = $this->connection->pdo();
        $stmt = $pdo->prepare("UPDATE {$this->table} SET token_version = token_version + 1 WHERE id = :id");
        $stmt->execute(['id' => $id]);
    }

    public function updateRememberToken(int|string $id, ?string $token): void
    {
        $pdo = $this->connection->pdo();
        $stmt = $pdo->prepare("UPDATE {$this->table} SET remember_token = :token WHERE id = :id");
        $stmt->execute(['token' => $token, 'id' => $id]);
    }

    // ── Private Helpers ──────────────────────────────────────────

    /**
     * Execute a query and hydrate the first row.
     *
     * @param array<string, mixed> $params
     */
    private function fetchOne(string $sql, array $params): ?AuthenticatableInterface
    {
        $pdo = $this->connection->pdo();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if ($row === false) {
            return null;
        }

        return $this->hydrate($row);
    }

    /**
     * Hydrate a database row into the configured model class.
     *
     * @param array<string, mixed> $row
     */
    private function hydrate(array $row): AuthenticatableInterface
    {
        $class = $this->modelClass;

        if (!class_exists($class)) {
            throw new \RuntimeException("User model class '{$class}' does not exist.");
        }

        if (method_exists($class, 'fromDatabaseRow')) {
            return $class::fromDatabaseRow($row);
        }

        // Reflection-based hydration
        $reflection = new \ReflectionClass($class);
        $user = $reflection->newInstanceWithoutConstructor();

        foreach ($row as $column => $value) {
            if ($reflection->hasProperty($column)) {
                $prop = $reflection->getProperty($column);
                $prop->setAccessible(true);
                $prop->setValue($user, $value);
            }
        }

        if (!$user instanceof AuthenticatableInterface) {
            throw new \RuntimeException("User model '{$class}' must implement AuthenticatableInterface.");
        }

        return $user;
    }
}
