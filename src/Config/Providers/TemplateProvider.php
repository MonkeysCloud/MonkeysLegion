<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Template\Compiler;
use MonkeysLegion\Template\Loader;
use MonkeysLegion\Template\Parser;
use MonkeysLegion\Template\Renderer;

/**
 * Template engine provider (parser, compiler, loader, renderer).
 *
 * HTTP-only context.
 */
final class TemplateProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            Parser::class => fn(): Parser => new Parser(),

            Compiler::class => fn($c): Compiler => new Compiler(
                $c->get(Parser::class),
            ),

            Loader::class => fn(): Loader => new Loader(
                sourcePath: base_path('resources/views'),
                cachePath: base_path('var/cache/views'),
            ),

            Renderer::class => static function ($c): Renderer {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new Renderer(
                    parser: $c->get(Parser::class),
                    compiler: $c->get(Compiler::class),
                    loader: $c->get(Loader::class),
                    cacheEnabled: $mlc->getBool('cache.enabled', true) ?? true,
                );
            },
        ];
    }
}
