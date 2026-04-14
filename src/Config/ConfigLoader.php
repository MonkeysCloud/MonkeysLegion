<?php

namespace MonkeysLegion\Config;

use MonkeysLegion\DI\Container;
use MonkeysLegion\Env\Contracts\EnvBootstrapperInterface;
use MonkeysLegion\Env\Contracts\EnvRepositoryInterface;
use MonkeysLegion\Mlc\{
    Cache\CompiledPhpCache,
    Config as MlcConfig,
    Loader as MlcLoader
};
use MonkeysLegion\Mlc\Contracts\LoaderInterface;
use MonkeysLegion\Mlc\Contracts\ParserInterface;
use MonkeysLegion\Mlc\Parsers\CompositeParser;
use MonkeysLegion\Mlc\Parsers\MlcParser;
use MonkeysLegion\Mlc\Parsers\PhpParser;

class ConfigLoader
{
    /** @return array<string, callable> */
    public function __invoke(): array
    {
        return [
            /* ----------------------------------------------------------------- */
            /* .env support                                                */
            /* ----------------------------------------------------------------- */
            EnvRepositoryInterface::class => static function (Container $c) {
                /**
                 * @var EnvBootstrapperInterface|null $envBootstrapper
                 */
                $envBootstrapper = $c->has(EnvBootstrapperInterface::class) ? $c->get(EnvBootstrapperInterface::class) : null;
                if (!$envBootstrapper) {
                    throw new \RuntimeException('EnvBootstrapperInterface is required to instantiate EnvRepositoryInterface. Please bind it in the container.');
                }
                return $envBootstrapper->getRepository();
            },

            /* ----------------------------------------------------------------- */
            /* .mlc config support                                                */
            /* ----------------------------------------------------------------- */
            ParserInterface::class                    => function (Container $c) {
                $envBootstrapper = $c->has(EnvBootstrapperInterface::class) ? $c->get(EnvBootstrapperInterface::class) : null;
                if (!$envBootstrapper) {
                    throw new \RuntimeException('EnvBootstrapperInterface is required to instantiate MlcParser. Please bind it in the container.');
                }
                $mlcParser = new MlcParser(envBootstrapper: $envBootstrapper, root: base_path());
                $phpParser = new PhpParser(envBootstrapper: $envBootstrapper, root: base_path());
                $compositeParser = new CompositeParser($mlcParser);
                $compositeParser->registerParser('php', $phpParser);
                return $compositeParser;
            },
            LoaderInterface::class,
            MlcLoader::class                => function (Container $c) {
                $env = env('APP_ENV', 'dev');
                $cacheDir = base_path('var/cache/mlc');
                $cache = new CompiledPhpCache($cacheDir);
                /** @var EnvRepositoryInterface|null $env */
                $env = $c->has(EnvRepositoryInterface::class) ? $c->get(EnvRepositoryInterface::class) : null;

                return new MlcLoader(
                    parser: $c->get(ParserInterface::class),
                    baseDir: base_path('config'),
                    cache: $cache,
                    strictSecurity: $env ? $env->getBool('MLC_STRICT_SECURITY', false) : false
                );
            },

            /* -----------------------------------------------------------------
             | Dynamic .mlc config loader
             | – picks up every *.mlc file in config/ at runtime
             * ---------------------------------------------------------------- */
            MlcConfig::class => static function (Container $c) {
                /** @var MlcLoader $loader */
                $loader = $c->get(MlcLoader::class);

                // 1 grab every *.mlc in the config dir
                $files = [
                    ...glob(base_path('config/*.mlc')) ?: [],
                    ...glob(base_path('config/*.php')) ?: []
                ];

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
