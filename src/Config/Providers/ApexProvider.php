<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Apex\AI;
use MonkeysLegion\Apex\Contract\ProviderInterface;
use MonkeysLegion\Apex\Cost\CostTracker;
use MonkeysLegion\Apex\Cost\PricingRegistry;
use MonkeysLegion\Apex\Provider\OpenAI\OpenAIProvider;
use MonkeysLegion\Mlc\Config as MlcConfig;

/**
 * Apex AI/ML provider.
 *
 * Uses the Apex package's AI facade with configurable provider backends.
 */
final class ApexProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            PricingRegistry::class => fn(): PricingRegistry => new PricingRegistry(),

            CostTracker::class => fn($c): CostTracker => new CostTracker(
                pricing: $c->get(PricingRegistry::class),
            ),

            ProviderInterface::class => static function ($c): ProviderInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $provider = $mlc->getString('apex.provider', 'openai') ?? 'openai';

                $apiKey = $mlc->getString('apex.api_key', '') ?? '';
                $model  = $mlc->getString('apex.model', 'gpt-4') ?? 'gpt-4';

                return match ($provider) {
                    'openai' => new OpenAIProvider(apiKey: $apiKey, model: $model),
                    default  => new OpenAIProvider(apiKey: $apiKey, model: $model),
                };
            },

            AI::class => fn($c): AI => new AI(
                provider: $c->get(ProviderInterface::class),
                costTracker: $c->get(CostTracker::class),
            ),
        ];
    }
}
