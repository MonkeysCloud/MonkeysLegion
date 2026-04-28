<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

/**
 * Contract for modular service-provider classes.
 *
 * This interface extends the lightweight contracts interface so that both
 * namespaces are interchangeable. External packages should implement
 * {@see \MonkeysLegion\Contracts\ServiceProviderInterface} directly
 * (from the `monkeyslegion-contracts` package) to avoid pulling in
 * the full framework.
 *
 * @see \MonkeysLegion\Contracts\ServiceProviderInterface
 */
interface ServiceProviderInterface extends \MonkeysLegion\Contracts\ServiceProviderInterface
{
    // All methods inherited from the contracts interface.
    // This interface exists for backward compatibility within the framework.
}
