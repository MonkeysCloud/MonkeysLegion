<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Contracts\AbstractServiceProvider as ContractsAbstractServiceProvider;

/**
 * Base class that provides sensible defaults for service providers.
 *
 * Extends the contracts base class and implements the framework-local
 * ServiceProviderInterface for full backward compatibility.
 *
 * Concrete providers only need to implement getDefinitions().
 */
abstract class AbstractServiceProvider extends ContractsAbstractServiceProvider implements ServiceProviderInterface
{
    // All defaults inherited from contracts AbstractServiceProvider.
    // This class exists for backward compatibility within the framework.
}
