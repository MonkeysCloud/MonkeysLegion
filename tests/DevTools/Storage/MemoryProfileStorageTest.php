<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Storage;

use MonkeysLegion\DevTools\Profiler\Profile;
use MonkeysLegion\DevTools\Profiler\ProfileContext;
use MonkeysLegion\DevTools\Storage\MemoryProfileStorage;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Storage\MemoryProfileStorage
 */
final class MemoryProfileStorageTest extends TestCase
{
    private function makeProfile(string $method = 'GET', string $uri = '/', int $status = 200): Profile
    {
        $ctx = ProfileContext::create('testing', true);
        return Profile::fromContext($ctx, hrtime(true) / 1e6 + 10, [], $method, $uri, $status);
    }

    public function testSaveAndFind(): void
    {
        $storage = new MemoryProfileStorage();
        $profile = $this->makeProfile();

        $storage->save($profile);

        $found = $storage->find($profile->id);
        $this->assertNotNull($found);
        $this->assertSame($profile->id, $found->id);
    }

    public function testFindReturnsNullForMissing(): void
    {
        $storage = new MemoryProfileStorage();
        $this->assertNull($storage->find('nonexistent'));
    }

    public function testLatestReturnsNewestFirst(): void
    {
        $storage = new MemoryProfileStorage();
        $p1 = $this->makeProfile(uri: '/first');
        $p2 = $this->makeProfile(uri: '/second');

        $storage->save($p1);
        $storage->save($p2);

        $latest = $storage->latest(10);
        $this->assertCount(2, $latest);
        $this->assertSame('/second', $latest[0]->uri);
        $this->assertSame('/first', $latest[1]->uri);
    }

    public function testLatestRespectsLimit(): void
    {
        $storage = new MemoryProfileStorage();
        for ($i = 0; $i < 10; $i++) {
            $storage->save($this->makeProfile());
        }

        $this->assertCount(3, $storage->latest(3));
    }

    public function testDelete(): void
    {
        $storage = new MemoryProfileStorage();
        $profile = $this->makeProfile();
        $storage->save($profile);

        $storage->delete($profile->id);

        $this->assertNull($storage->find($profile->id));
        $this->assertSame(0, $storage->count());
    }

    public function testClear(): void
    {
        $storage = new MemoryProfileStorage();
        $storage->save($this->makeProfile());
        $storage->save($this->makeProfile());

        $cleared = $storage->clear();

        $this->assertSame(2, $cleared);
        $this->assertSame(0, $storage->count());
    }

    public function testCountAndSizePropertyHook(): void
    {
        $storage = new MemoryProfileStorage();
        $this->assertSame(0, $storage->size);

        $storage->save($this->makeProfile());
        $this->assertSame(1, $storage->size);
        $this->assertSame(1, $storage->count());
    }

    public function testQueryByMethod(): void
    {
        $storage = new MemoryProfileStorage();
        $storage->save($this->makeProfile(method: 'GET'));
        $storage->save($this->makeProfile(method: 'POST'));
        $storage->save($this->makeProfile(method: 'GET'));

        $gets = $storage->query(['method' => 'GET']);
        $this->assertCount(2, $gets);
    }

    public function testQueryByStatusRange(): void
    {
        $storage = new MemoryProfileStorage();
        $storage->save($this->makeProfile(status: 200));
        $storage->save($this->makeProfile(status: 404));
        $storage->save($this->makeProfile(status: 500));

        $errors = $storage->query(['status_min' => 400]);
        $this->assertCount(2, $errors);
    }

    public function testQueryByUri(): void
    {
        $storage = new MemoryProfileStorage();
        $storage->save($this->makeProfile(uri: '/api/users'));
        $storage->save($this->makeProfile(uri: '/api/posts'));
        $storage->save($this->makeProfile(uri: '/admin/dashboard'));

        $apiOnly = $storage->query(['uri' => '/api/']);
        $this->assertCount(2, $apiOnly);
    }

    public function testPruneReturnsZero(): void
    {
        $storage = new MemoryProfileStorage();
        $this->assertSame(0, $storage->prune());
    }
}
