<?php

declare(strict_types=1);

namespace MonkeysLegion\Framework\Attributes;

use Attribute;

/**
 * Declares that a provider must be booted after another provider.
 *
 * Used by the Application boot sequence to topologically sort providers.
 *
 * Example:
 *   #[BootAfter(DatabaseProvider::class)]
 *   final class RepositoryProvider extends AbstractServiceProvider { ... }
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class BootAfter
{
    public function __construct(
        public readonly string $dependency,
    ) {}
}
