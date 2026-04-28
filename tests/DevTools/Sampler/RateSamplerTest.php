<?php

declare(strict_types=1);

namespace MonkeysLegion\Tests\DevTools\Sampler;

use MonkeysLegion\DevTools\Sampler\RateSampler;
use PHPUnit\Framework\TestCase;

/**
 * @covers \MonkeysLegion\DevTools\Sampler\RateSampler
 */
final class RateSamplerTest extends TestCase
{
    public function testAlwaysSamplesAt100Percent(): void
    {
        $sampler = new RateSampler(defaultRate: 1.0);

        for ($i = 0; $i < 100; $i++) {
            $this->assertTrue($sampler->shouldSample("req-$i", 'local'));
        }
    }

    public function testNeverSamplesAtZeroPercent(): void
    {
        $sampler = new RateSampler(defaultRate: 0.0);

        for ($i = 0; $i < 100; $i++) {
            $this->assertFalse($sampler->shouldSample("req-$i", 'local'));
        }
    }

    public function testEnvironmentOverride(): void
    {
        $sampler = new RateSampler(
            defaultRate: 1.0,
            environmentRates: ['production' => 0.0],
        );

        $this->assertTrue($sampler->shouldSample('r1', 'local'));
        $this->assertFalse($sampler->shouldSample('r1', 'production'));
    }

    public function testRateMethod(): void
    {
        $sampler = new RateSampler(
            defaultRate: 0.5,
            environmentRates: ['production' => 0.1],
        );

        $this->assertEqualsWithDelta(0.5, $sampler->rate('local'), 0.001);
        $this->assertEqualsWithDelta(0.1, $sampler->rate('production'), 0.001);
    }

    public function testEffectiveRateIsClamped(): void
    {
        $sampler = new RateSampler(defaultRate: 2.0);
        $this->assertEqualsWithDelta(1.0, $sampler->effectiveRate, 0.001);

        $sampler2 = new RateSampler(defaultRate: -0.5);
        $this->assertEqualsWithDelta(0.0, $sampler2->effectiveRate, 0.001);
    }

    public function testDeterministicSampling(): void
    {
        $sampler = new RateSampler(defaultRate: 0.5, deterministic: true);

        // Same request ID should always give same result
        $result1 = $sampler->shouldSample('fixed-id-123', 'local');
        $result2 = $sampler->shouldSample('fixed-id-123', 'local');

        $this->assertSame($result1, $result2);
    }

    public function testRateClampedInMethod(): void
    {
        $sampler = new RateSampler(
            defaultRate: 1.0,
            environmentRates: ['test' => 5.0],
        );

        $this->assertEqualsWithDelta(1.0, $sampler->rate('test'), 0.001);
    }
}
