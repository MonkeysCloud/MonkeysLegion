<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\Sockets\Registry;

use MonkeysLegion\Sockets\Contracts\ConnectionInterface;
use MonkeysLegion\Sockets\Contracts\MessageInterface;
use MonkeysLegion\Sockets\Registry\ConnectionRegistry;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\Sockets\Registry\ConnectionRegistry
 */
final class ConnectionRegistryTest extends TestCase
{
    private function makeConnection(string $id): ConnectionInterface
    {
        return new class($id) implements ConnectionInterface {
            public function __construct(private string $id) {}
            public function getId(): string { return $this->id; }
            public function send(string|MessageInterface $m): void {}
            public function ping(string $p = ''): void {}
            public function close(int $code = 1000, string $reason = ''): void {}
            public function lastActivity(): int { return time(); }
            public function touch(): void {}
            public function getMetadata(): array { return []; }
        };
    }

    public function testAddAndGet(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');

        $registry->add($conn);

        $this->assertSame($conn, $registry->get('c1'));
        $this->assertSame(1, $registry->count());
    }

    public function testRemoveById(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');
        $registry->add($conn);

        $registry->remove('c1');

        $this->assertNull($registry->get('c1'));
        $this->assertSame(0, $registry->count());
    }

    public function testRemoveByObject(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');
        $registry->add($conn);

        $registry->remove($conn);
        $this->assertNull($registry->get('c1'));
    }

    public function testRemoveNonexistentIsNoop(): void
    {
        $registry = new ConnectionRegistry();
        $registry->remove('nonexistent'); // Should not throw
        $this->assertSame(0, $registry->count());
    }

    public function testTagAndGetByTag(): void
    {
        $registry = new ConnectionRegistry();
        $c1 = $this->makeConnection('c1');
        $c2 = $this->makeConnection('c2');
        $registry->add($c1);
        $registry->add($c2);

        $registry->tag($c1, 'room:lobby');
        $registry->tag($c2, 'room:lobby');

        $tagged = iterator_to_array($registry->getByTag('room:lobby'));
        $this->assertCount(2, $tagged);
    }

    public function testUntagRemovesFromGroup(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');
        $registry->add($conn);
        $registry->tag($conn, 'room:A');

        $registry->untag($conn, 'room:A');

        $tagged = iterator_to_array($registry->getByTag('room:A'));
        $this->assertCount(0, $tagged);
    }

    public function testRemoveCleansTags(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');
        $registry->add($conn);
        $registry->tag($conn, 'room:A');
        $registry->tag($conn, 'room:B');

        $registry->remove($conn);

        $this->assertCount(0, iterator_to_array($registry->getByTag('room:A')));
        $this->assertCount(0, iterator_to_array($registry->getByTag('room:B')));
    }

    public function testCountPropertyHook(): void
    {
        $registry = new ConnectionRegistry();
        $this->assertSame(0, $registry->count);

        $registry->add($this->makeConnection('c1'));
        $registry->add($this->makeConnection('c2'));
        $this->assertSame(2, $registry->count);
    }

    public function testAllReturnsAllConnections(): void
    {
        $registry = new ConnectionRegistry();
        $registry->add($this->makeConnection('c1'));
        $registry->add($this->makeConnection('c2'));

        $all = $registry->all();
        $this->assertCount(2, $all);
    }

    public function testIsIterable(): void
    {
        $registry = new ConnectionRegistry();
        $registry->add($this->makeConnection('c1'));

        $ids = [];
        foreach ($registry as $id => $conn) {
            $ids[] = $id;
        }

        $this->assertSame(['c1'], $ids);
    }

    public function testTagByStringId(): void
    {
        $registry = new ConnectionRegistry();
        $conn = $this->makeConnection('c1');
        $registry->add($conn);

        $registry->tag('c1', 'vip');

        $tagged = iterator_to_array($registry->getByTag('vip'));
        $this->assertCount(1, $tagged);
    }
}
