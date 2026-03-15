<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Framework\Middleware\CallableMiddlewareAdapter;
use MonkeysLegion\I18n\LocaleManager;
use MonkeysLegion\I18n\Middleware\LocaleMiddleware;
use MonkeysLegion\I18n\Translator;
use MonkeysLegion\I18n\TranslatorFactory;
use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Template\Compiler as TemplateCompiler;
use MonkeysLegion\Template\Loader as TemplateLoader;
use MonkeysLegion\Template\Parser as TemplateParser;
use MonkeysLegion\Template\Renderer as TemplateRenderer;
use Psr\SimpleCache\CacheInterface;

final class TemplateProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'http';
    }

    public function getDefinitions(): array
    {
        return [
            /* Template engine */
            TemplateParser::class   => fn()   => new TemplateParser(),
            TemplateCompiler::class => fn($c) => new TemplateCompiler($c->get(TemplateParser::class)),
            TemplateLoader::class   => fn()   => new TemplateLoader(
                base_path('resources/views'),
                base_path('var/cache/views')
            ),
            TemplateRenderer::class => fn($c) => new TemplateRenderer(
                $c->get(TemplateParser::class),
                $c->get(TemplateCompiler::class),
                $c->get(TemplateLoader::class),
                (bool) $c->get(MlcConfig::class)->get('cache.enabled', true)
            ),

            /* I18n */
            Translator::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return TranslatorFactory::create([
                    'locale'   => $mlc->get('app.locale', 'en'),
                    'fallback' => $mlc->get('app.fallback_locale', 'en'),
                    'path'     => base_path('resources/lang'),
                    'cache'    => $mlc->get('cache.enabled', true) ? $c->get(CacheInterface::class) : null,
                ]);
            },

            LocaleManager::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return TranslatorFactory::createLocaleManager([
                    'default'   => $mlc->get('app.locale', 'en'),
                    'fallback'  => $mlc->get('app.fallback_locale', 'en'),
                    'supported' => $mlc->get('app.supported_locales', ['en']),
                    'detectors' => $mlc->get('app.locale_detectors', ['url', 'session', 'cookie', 'header']),
                ]);
            },

            LocaleMiddleware::class => static function ($c) {
                $localeMiddleware = new LocaleMiddleware(
                    $c->get(LocaleManager::class),
                    $c->get(Translator::class)
                );

                return new CallableMiddlewareAdapter($localeMiddleware);
            },
        ];
    }
}
