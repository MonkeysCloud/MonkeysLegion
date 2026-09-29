<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Markdown\MarkdownRenderer;

/**
 * Markdown service provider.
 *
 * Registers the MarkdownRenderer as a singleton — it is a pure PHP
 * renderer with no configuration needed.
 */
final class MarkdownProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            MarkdownRenderer::class => static fn(): MarkdownRenderer => new MarkdownRenderer(),
        ];
    }
}
