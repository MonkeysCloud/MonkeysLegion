<?php

namespace MonkeysLegion\Config;

use MonkeysLegion\Mlc\{
    Config as MlcConfig,
    Loader as MlcLoader,
    Parser as MlcParser
};
use MonkeysLegion\Http\SimpleFileCache;

class ConfigLoader
{
    /** @return array<string, callable> */
    public function __invoke(): array
    {
        return [
            /* ----------------------------------------------------------------- */
            /* .mlc config support                                                */
            /* ----------------------------------------------------------------- */
            MlcParser::class                    => fn()   => new MlcParser(),
            MlcLoader::class                    => fn($c) => new MlcLoader(
                $c->get(MlcParser::class),
                base_path('config'),
                base_path(),
                new SimpleFileCache(base_path('var/cache/mlc'))
            ),

            /* -----------------------------------------------------------------
             | Dynamic .mlc config loader
             | – picks up every *.mlc file in config/ at runtime
             * ---------------------------------------------------------------- */
            MlcConfig::class => static function ($c) {
                /** @var MlcLoader $loader */
                $loader = $c->get(MlcLoader::class);

                // 1 grab every *.mlc in the config dir
                $files = glob(base_path('config/*.mlc')) ?: [];

                // 2 turn "config/foo.mlc" into just "foo"
                $names = array_map(
                    static fn(string $path) => pathinfo($path, PATHINFO_FILENAME),
                    $files
                );

                // 3 deterministic order (alpha) so overrides are stable
                sort($names);

                return $loader->load($names);
            },
        ];
    }
}
