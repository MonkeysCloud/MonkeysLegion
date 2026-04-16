<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Framework\Auth;

use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Framework\Auth\DatabaseUserProvider;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Framework\Auth\DatabaseUserProvider
 */
final class DatabaseUserProviderTest extends TestCase
{
    private \PDO $pdo;
    private ConnectionInterface $connection;

    protected function setUp(): void
    {
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        // Create users table
        $this->pdo->exec('CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            api_key TEXT,
            remember_token TEXT,
            token_version INTEGER DEFAULT 0
        )');

        // Insert a test user
        $this->pdo->exec("INSERT INTO users (email, password, api_key, token_version) VALUES ('test@example.com', 'hashed_pw', 'key123', 0)");

        // Mock ConnectionInterface
        /** @var ConnectionInterface&\PHPUnit\Framework\MockObject\MockObject $connection */
        $connection = $this->createMock(ConnectionInterface::class);
        $connection->expects($this->any())->method('pdo')->willReturn($this->pdo);
        $this->connection = $connection;
    }

    public function testFindByIdReturnsNullForMissingId(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $this->assertNull($provider->findById(999));
    }

    public function testFindByIdReturnsUserForExistingId(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $user = $provider->findById(1);

        $this->assertNotNull($user);
        $this->assertInstanceOf(AuthenticatableInterface::class, $user);
    }

    public function testFindByEmailReturnsUser(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $user = $provider->findByEmail('test@example.com');

        $this->assertNotNull($user);
    }

    public function testFindByEmailReturnsNullForUnknown(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $this->assertNull($provider->findByEmail('unknown@example.com'));
    }

    public function testFindByApiKeyReturnsUser(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $user = $provider->findByApiKey('key123');

        $this->assertNotNull($user);
    }

    public function testFindByApiKeyReturnsNullForUnknown(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $this->assertNull($provider->findByApiKey('bad_key'));
    }

    public function testFindByRememberTokenReturnsNullIfNoMatch(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $this->assertNull($provider->findByRememberToken(1, 'no_such_token'));
    }

    public function testFindByRememberTokenReturnsUserIfMatch(): void
    {
        $this->pdo->exec("UPDATE users SET remember_token = 'remember_me' WHERE id = 1");

        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $user = $provider->findByRememberToken(1, 'remember_me');
        $this->assertNotNull($user);
    }

    public function testCreateInsertsAndReturnsUser(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $user = $provider->create([
            'email'    => 'new@example.com',
            'password' => 'secret_hash',
        ]);

        $this->assertNotNull($user);
        $this->assertInstanceOf(AuthenticatableInterface::class, $user);

        // Verify in DB
        $stmt = $this->pdo->query("SELECT email FROM users WHERE email = 'new@example.com'");
        $this->assertSame('new@example.com', $stmt->fetchColumn());
    }

    public function testUpdatePasswordChangesPassword(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $provider->updatePassword(1, 'new_hash');

        $stmt = $this->pdo->prepare('SELECT password FROM users WHERE id = 1');
        $stmt->execute();

        $this->assertSame('new_hash', $stmt->fetchColumn());
    }

    public function testIncrementTokenVersionIncrements(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $provider->incrementTokenVersion(1);

        $stmt = $this->pdo->prepare('SELECT token_version FROM users WHERE id = 1');
        $stmt->execute();

        $this->assertSame(1, (int) $stmt->fetchColumn());

        $provider->incrementTokenVersion(1);

        $stmt->execute();
        $this->assertSame(2, (int) $stmt->fetchColumn());
    }

    public function testUpdateRememberTokenSetsToken(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $provider->updateRememberToken(1, 'new_remember');

        $stmt = $this->pdo->prepare('SELECT remember_token FROM users WHERE id = 1');
        $stmt->execute();

        $this->assertSame('new_remember', $stmt->fetchColumn());
    }

    public function testUpdateRememberTokenClearsToken(): void
    {
        $this->pdo->exec("UPDATE users SET remember_token = 'old_token' WHERE id = 1");

        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUser::class,
        );

        $provider->updateRememberToken(1, null);

        $stmt = $this->pdo->prepare('SELECT remember_token FROM users WHERE id = 1');
        $stmt->execute();

        $this->assertNull($stmt->fetchColumn() ?: null);
    }

    public function testThrowsForNonExistentModelClass(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: 'NonExistent\\Model\\User',
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("User model class 'NonExistent\\Model\\User' does not exist");

        $provider->findById(1);
    }

    public function testHydrateUsesFromDatabaseRowIfAvailable(): void
    {
        $provider = new DatabaseUserProvider(
            connection: $this->connection,
            modelClass: TestAuthUserWithFactory::class,
        );

        $user = $provider->findById(1);

        $this->assertNotNull($user);
        $this->assertInstanceOf(TestAuthUserWithFactory::class, $user);
    }
}

/**
 * Test stub implementing AuthenticatableInterface via reflection hydration.
 */
class TestAuthUser implements AuthenticatableInterface
{
    public int|string $id = 0;
    public string $email = '';
    public string $password = '';
    public ?string $api_key = null;
    public ?string $remember_token = null;
    public int $token_version = 0;

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return $this->password;
    }

    public function getRememberToken(): ?string
    {
        return $this->remember_token;
    }

    public function setRememberToken(?string $token): void
    {
        $this->remember_token = $token;
    }

    public function getTokenVersion(): int
    {
        return $this->token_version;
    }
}

/**
 * Test stub with fromDatabaseRow factory method.
 */
class TestAuthUserWithFactory extends TestAuthUser
{
    public static function fromDatabaseRow(array $row): self
    {
        $user = new self();
        $user->id = (int) ($row['id'] ?? 0);
        $user->email = $row['email'] ?? '';
        $user->password = $row['password'] ?? '';

        return $user;
    }
}
