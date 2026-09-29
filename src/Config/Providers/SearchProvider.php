<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Search\Engines\DatabaseEngine;
use MonkeysLegion\Search\Engines\MeilisearchEngine;
use MonkeysLegion\Search\Engines\NullEngine;
use MonkeysLegion\Search\SearchManager;
use PDO;

/**
 * Search service provider.
 *
 * Registers the SearchManager and engine based on config:
 *   search {
 *       driver = ${SEARCH_DRIVER:null}
 *       meilisearch { host = ${MEILISEARCH_HOST} key = ${MEILISEARCH_KEY} }
 *   }
 */
final class SearchProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            SearchManager::class => static function ($c): SearchManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $driver = $mlc->getString('search.driver', 'null') ?? 'null';

                $engine = match ($driver) {
                    'database' => new DatabaseEngine($c->get(PDO::class)),
                    'meilisearch' => new MeilisearchEngine(
                        $mlc->getString('search.meilisearch.host', 'http://localhost:7700') ?? 'http://localhost:7700',
                        $mlc->getString('search.meilisearch.key', '') ?? '',
                    ),
                    default => new NullEngine(),
                };

                return new SearchManager($engine);
            },
        ];
    }
}
