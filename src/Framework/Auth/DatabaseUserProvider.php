<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Auth;

use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use RuntimeException;

class DatabaseUserProvider implements UserProviderInterface
{
    public function __construct(
        private ConnectionInterface $connection,
        private string $table = 'users',
        private string $modelClass = 'App\\Entity\\User'
    ) {}

    public function findById(int|string $id): ?AuthenticatableInterface
    {
        $stmt = $this->connection->pdo()->prepare("SELECT * FROM {$this->table} WHERE id = :id LIMIT 1");
        $stmt->execute(['id' => $id]);
        $data = $stmt->fetch(\PDO::FETCH_ASSOC);

        return $data ? $this->hydrate($data) : null;
    }

    public function findByEmail(string $email): ?AuthenticatableInterface
    {
        $stmt = $this->connection->pdo()->prepare("SELECT * FROM {$this->table} WHERE email = :email LIMIT 1");
        $stmt->execute(['email' => $email]);
        $data = $stmt->fetch(\PDO::FETCH_ASSOC);

        return $data ? $this->hydrate($data) : null;
    }

    public function findByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (empty($credentials)) {
            return null;
        }

        $conditions = [];
        $params = [];
        foreach ($credentials as $key => $value) {
            if ($key === 'password') {
                continue;
            }
            $conditions[] = "{$key} = :{$key}";
            $params[$key] = $value;
        }

        if (empty($conditions)) {
            return null;
        }

        $sql = "SELECT * FROM {$this->table} WHERE " . implode(' AND ', $conditions) . " LIMIT 1";
        $stmt = $this->connection->pdo()->prepare($sql);
        $stmt->execute($params);
        $data = $stmt->fetch(\PDO::FETCH_ASSOC);

        return $data ? $this->hydrate($data) : null;
    }

    public function incrementTokenVersion(int|string $userId): void
    {
        $stmt = $this->connection->pdo()->prepare("UPDATE {$this->table} SET token_version = token_version + 1 WHERE id = :id");
        $stmt->execute(['id' => $userId]);
    }

    public function create(array $attributes): AuthenticatableInterface
    {
        $columns = array_keys($attributes);
        $placeholders = array_map(fn($col) => ':' . $col, $columns);

        $sql = "INSERT INTO {$this->table} (" . implode(', ', $columns) . ") VALUES (" . implode(', ', $placeholders) . ")";
        $stmt = $this->connection->pdo()->prepare($sql);
        $stmt->execute($attributes);

        $id = $this->connection->pdo()->lastInsertId();

        // Fetch the created user to return full object (or just hydrate manually)
        $attributes['id'] = $id;
        // Default token_version if not set
        if (!isset($attributes['token_version'])) {
            $attributes['token_version'] = 0;
        }

        return $this->hydrate($attributes);
    }

    public function updatePassword(int|string $userId, string $passwordHash): void
    {
        $stmt = $this->connection->pdo()->prepare("UPDATE {$this->table} SET password = :password WHERE id = :id");
        $stmt->execute(['password' => $passwordHash, 'id' => $userId]);
    }

    private function hydrate(array $data): AuthenticatableInterface
    {
        if (!class_exists($this->modelClass)) {
            throw new RuntimeException("User model class '{$this->modelClass}' not found.");
        }

        // Simple hydration assuming public properties or constructor parameters matching keys could be complex.
        // For now, we'll try to instantiate and set properties if it has a constructor or just set properties.
        // A robust implementation would use a hydrator. Here we assume the entity might have a static 'fromArray' or similar, 
        // strictly speaking we should check.
        // Let's assume a simple constructor or property assignment.

        $user = new $this->modelClass();

        // This is a naive hydrator.
        foreach ($data as $key => $value) {
            if (property_exists($user, $key)) {

                // Handle property visibility via reflection to be safe
                $reflection = new \ReflectionProperty($user, $key);
                if (!$reflection->isPublic()) {
                    $reflection->setAccessible(true);
                }
                $reflection->setValue($user, $value);
            }
        }

        if (!$user instanceof AuthenticatableInterface) {
            throw new RuntimeException("User model '{$this->modelClass}' must implement AuthenticatableInterface.");
        }

        return $user;
    }
}
