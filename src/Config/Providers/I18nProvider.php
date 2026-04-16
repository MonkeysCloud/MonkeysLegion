<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\I18n\Loaders\FileLoader;
use MonkeysLegion\I18n\LocaleManager;
use MonkeysLegion\I18n\Middleware\LocaleMiddleware;
use MonkeysLegion\I18n\Translator;
use MonkeysLegion\Mlc\Config as MlcConfig;

/**
 * Internationalization (i18n) provider.
 *
 * Uses the I18n package's Translator, LocaleManager, and FileLoader.
 */
final class I18nProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            FileLoader::class => static function ($c): FileLoader {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new FileLoader(
                    base_path($mlc->getString('i18n.path', 'resources/lang') ?? 'resources/lang'),
                );
            },

            Translator::class => static function ($c): Translator {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $defaultLocale = $mlc->getString('i18n.locale', 'en') ?? 'en';
                $fallback = $mlc->getString('i18n.fallback', $defaultLocale) ?? $defaultLocale;

                return new Translator(
                    locale: $defaultLocale,
                    fallbackLocale: $fallback,
                );
            },

            LocaleManager::class => static function ($c): LocaleManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new LocaleManager(
                    defaultLocale: $mlc->getString('i18n.locale', 'en') ?? 'en',
                    supportedLocales: $mlc->getArray('i18n.supported_locales', ['en']) ?? ['en'],
                    fallbackLocale: $mlc->getString('i18n.fallback', 'en') ?? 'en',
                );
            },

            LocaleMiddleware::class => fn($c): LocaleMiddleware => new LocaleMiddleware(
                manager: $c->get(LocaleManager::class),
                translator: $c->get(Translator::class),
            ),
        ];
    }
}
