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
 *
 * Supports OAuth-linked accounts: findByOAuthProvider() resolves
 * users who have linked a social identity (Google, GitHub, etc.)
 * via a provider_id column on the user table or a separate
 * user_oauth_identities table for multi-provider support.
 */

final class DatabaseUserProvider implements UserProviderInterface
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly string $table = 'users',
        private readonly string $modelClass = 'App\\Entity\\User',
        private readonly string $oauthTable = 'user_oauth_identities',
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

    // ── OAuth / Socialite ──────────────────────────────────────────

    /**
     * Find a user by their OAuth provider identity.
     *
     * First checks a provider-specific column (e.g. google_id) on the
     * user table. If not found, checks the user_oauth_identities table
     * that allows multiple providers per user.
     *
     * @param string $provider OAuth provider name (google, github, etc.)
     * @param string $providerId The provider's unique user ID
     */
    public function findByOAuthProvider(string $provider, string $providerId): ?AuthenticatableInterface
    {
        // 1. Try provider column on user table (e.g. google_id, github_id)
        $column = $provider . '_id';
        $user = $this->fetchOne(
            "SELECT * FROM {$this->table} WHERE {$column} = :provider_id LIMIT 1",
            ['provider_id' => $providerId],
        );

        if ($user !== null) {
            return $user;
        }

        // 2. Try user_oauth_identities table (multiple providers per user)
        $sql = "SELECT u.* FROM {$this->table} u"
             . " INNER JOIN {$this->oauthTable} o ON o.user_id = u.id"
             . " WHERE o.provider = :provider AND o.provider_id = :provider_id"
             . " LIMIT 1";

        return $this->fetchOne($sql, ['provider' => $provider, 'provider_id' => $providerId]);
    }

    /**
     * Link an OAuth provider identity to an existing user.
     *
     * If a provider-specific column exists on the user table, it is
     * updated. Otherwise, a row is inserted into user_oauth_identities.
     *
     * @param int|string $userId    The local user ID
     * @param string     $provider  OAuth provider name
     * @param string     $providerId The provider's unique user ID
     * @param array<string, mixed> $extra Additional metadata (token, refresh_token, etc.)
     */
    public function linkOAuthProvider(
        int|string $userId,
        string $provider,
        string $providerId,
        array $extra = [],
    ): void {
        $pdo = $this->connection->pdo();
        $column = $provider . '_id';

        // Try updating a provider column on the user table
        $stmt = $pdo->prepare(
            "UPDATE {$this->table} SET {$column} = :provider_id WHERE id = :user_id",
        );
        $stmt->execute(['provider_id' => $providerId, 'user_id' => $userId]);

        // If no rows affected, the column likely does not exist — use identity table
        if ($stmt->rowCount() === 0) {
            $metadata = json_encode($extra, JSON_THROW_ON_ERROR);
            $sql = "INSERT INTO {$this->oauthTable}"
                . " (user_id, provider, provider_id, metadata, created_at)"
                . " VALUES (:user_id, :provider, :provider_id, :metadata, NOW())"
                . " ON DUPLICATE KEY UPDATE metadata = :metadata, updated_at = NOW()";

            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                'user_id' => $userId,
                'provider' => $provider,
                'provider_id' => $providerId,
                'metadata' => $metadata,
            ]);
        }
    }

    /**
     * Unlink an OAuth provider from a user.
     *
     * @param int|string $userId   The local user ID
     * @param string     $provider OAuth provider name
     */
    public function unlinkOAuthProvider(int|string $userId, string $provider): void
    {
        $pdo = $this->connection->pdo();
        $column = $provider . '_id';

        // Clear the provider column on the user table
        $stmt = $pdo->prepare(
            "UPDATE {$this->table} SET {$column} = NULL WHERE id = :user_id AND {$column} IS NOT NULL",
        );
        $stmt->execute(['user_id' => $userId]);

        // Also remove from the identity table
        $stmt = $pdo->prepare(
            "DELETE FROM {$this->oauthTable} WHERE user_id = :user_id AND provider = :provider",
        );
        $stmt->execute(['user_id' => $userId, 'provider' => $provider]);
    }

    /**
     * Create or find a user from OAuth provider data.
     *
     * If the user already exists (by provider ID or email), returns it.
     * Otherwise, creates a new user with the OAuth data.
     *
     * @param string                $provider OAuth provider name
     * @param array<string, mixed> $oauthData Provider user data (email, name, id, etc.)
     */
    public function findOrCreateFromOAuth(string $provider, array $oauthData): AuthenticatableInterface
    {
        $providerId = (string) ($oauthData['id'] ?? '');
        $email = (string) ($oauthData['email'] ?? '');

        // 1. Find by provider ID
        if ($providerId !== '') {
            $user = $this->findByOAuthProvider($provider, $providerId);
            if ($user !== null) {
                return $user;
            }
        }

        // 2. Find by email, then link the provider
        if ($email !== '') {
            $user = $this->findByEmail($email);
            if ($user !== null) {
                if ($providerId !== '') {
                    $this->linkOAuthProvider($user->getAuthIdentifier(), $provider, $providerId, $oauthData);
                }
                return $user;
            }
        }

        // 3. Create new user from OAuth data
        $column = $provider . '_id';
        $attributes = [
            'name' => $oauthData['name'] ?? $oauthData['nickname'] ?? 'User',
            'email' => $email !== '' ? $email : ($providerId . '@' . $provider . '.oauth'),
            'password' => password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT),
            'active' => 1,
            $column => $providerId,
        ];

        $user = $this->create($attributes);

        // Also insert into identity table for multi-provider support
        if ($providerId !== '') {
            $this->linkOAuthProvider($user->getAuthIdentifier(), $provider, $providerId, $oauthData);
        }

        return $user;
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

                // Cast value to match the property's declared type
                $value = $this->castValue($prop, $value);

                $prop->setValue($user, $value);
            }
        }

        if (!$user instanceof AuthenticatableInterface) {
            throw new \RuntimeException("User model '{$class}' must implement AuthenticatableInterface.");
        }

        return $user;
    }

    /**
     * Cast a raw database value to match the property's declared type.
     *
     * Prevents TypeError when assigning string values from PDO
     * to typed properties (e.g. DateTimeImmutable, int, bool, array).
     */
    private function castValue(\ReflectionProperty $prop, mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }

        $type = $prop->getType();
        if (!$type instanceof \ReflectionNamedType) {
            return $value;
        }

        $typeName = $type->getName();

        return match ($typeName) {
            'DateTimeImmutable' => $value instanceof \DateTimeImmutable ? $value : new \DateTimeImmutable((string) $value),
            'DateTime'          => $value instanceof \DateTime ? $value : new \DateTime((string) $value),
            'int'               => (int) $value,
            'float'             => (float) $value,
            'bool'              => (bool) $value,
            'array'             => is_string($value) ? (json_decode($value, true) ?? []) : (array) $value,
            default             => $value,
        };
    }
}
