<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Attributes;

use Attribute;

/**
 * Marks a class as an auto-discovered service provider.
 *
 * The ProviderScanner will detect classes annotated with this attribute
 * and register them during the container build phase.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class Provider
{
    /**
     * @param int    $priority Higher priority providers are loaded first (default: 0)
     * @param string $context  'all', 'http', or 'cli'
     */
    public function __construct(
        public readonly int $priority = 0,
        public readonly string $context = 'all',
    ) {}
}
