<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Inertia\Inertia;
use MonkeysLegion\Inertia\InertiaMiddleware;
use MonkeysLegion\Inertia\ResponseFactory;
use MonkeysLegion\Mlc\Config as MlcConfig;

/**
 * Inertia.js service provider.
 *
 * Registers the Inertia service, middleware, and response factory.
 * Supports optional SSR via Node.js server.
 *
 * Required MLC block (config/app.mlc):
 *   inertia {
 *       ssr {
 *           enabled = ${INERTIA_SSR:false}
 *           url     = "http://localhost:13714"
 *       }
 *       root_view = "layouts.inertia-app"
 *   }
 */
final class InertiaProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            Inertia::class => static function ($c): Inertia {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $inertia = new Inertia();

                // Set root view if configured
                $rootView = $mlc->getString('inertia.root_view');
                if ($rootView !== null && $rootView !== '') {
                    $inertia->rootView($rootView);
                }

                // Enable SSR if configured
                $ssrEnabled = $mlc->getBool('inertia.ssr.enabled', false) ?? false;
                if ($ssrEnabled) {
                    $ssrUrl = $mlc->getString('inertia.ssr.url', 'http://localhost:13714') ?? 'http://localhost:13714';
                    $inertia->enableSsr($ssrUrl);
                }

                return $inertia;
            },

            ResponseFactory::class => static fn($c): ResponseFactory => new ResponseFactory(
                $c->get(Inertia::class),
            ),

            InertiaMiddleware::class => static fn($c): InertiaMiddleware => new InertiaMiddleware(
                $c->get(Inertia::class),
            ),
        ];
    }
}
