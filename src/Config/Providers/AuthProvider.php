<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Guard\AuthManager;
use MonkeysLegion\Auth\Guard\JwtGuard;
use MonkeysLegion\Auth\Guard\SessionGuard;
use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;
use MonkeysLegion\Auth\Middleware\RateLimitMiddleware as AuthRateLimitMiddleware;
use MonkeysLegion\Auth\Policy\Gate;
use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Storage\InMemoryTokenStorage;
use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Framework\Auth\DatabaseUserProvider;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;

/**
 * Authentication, authorization, guards, and RBAC provider.
 *
 * Uses the Auth package's AuthManager + Guard pattern.
 */
final class AuthProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Password Hasher */
            PasswordHasher::class => static function ($c): PasswordHasher {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $algorithm = match ($mlc->getString('auth.password.algorithm', 'default')) {
                    'bcrypt'   => PASSWORD_BCRYPT,
                    'argon2id' => PASSWORD_ARGON2ID,
                    default    => null,
                };

                return new PasswordHasher(
                    algorithm: $algorithm,
                    bcryptCost: $mlc->getInt('auth.password.cost', 12) ?? 12,
                );
            },

            /* JWT Service */
            JwtService::class => static function ($c): JwtService {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new JwtService(
                    secret: $mlc->getString('auth.jwt_secret', '') ?? '',
                    accessTtl: $mlc->getInt('auth.access_ttl', 1800) ?? 1800,
                    refreshTtl: $mlc->getInt('auth.refresh_ttl', 604800) ?? 604800,
                    leeway: $mlc->getInt('auth.jwt_leeway', 60) ?? 60,
                    issuer: $mlc->getString('auth.issuer'),
                    audience: $mlc->getString('auth.audience'),
                );
            },

            /* Rate Limiter */
            RateLimiterInterface::class => fn(): RateLimiterInterface => new InMemoryRateLimiter(),

            /* User Provider */
            UserProviderInterface::class => static function ($c): UserProviderInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new DatabaseUserProvider(
                    connection: $c->get(ConnectionInterface::class),
                    table: $mlc->getString('auth.users.table', 'users') ?? 'users',
                    modelClass: $mlc->getString('auth.users.model', 'App\\Entity\\User') ?? 'App\\Entity\\User',
                );
            },

            /* Token Storage */
            TokenStorageInterface::class => fn(): TokenStorageInterface => new InMemoryTokenStorage(),

            /* Two-Factor */
            TotpProvider::class => fn(): TotpProvider => new TotpProvider(),

            /* Core Auth Service */
            AuthService::class => static function ($c): AuthService {
                return new AuthService(
                    users: $c->get(UserProviderInterface::class),
                    hasher: $c->get(PasswordHasher::class),
                    jwt: $c->get(JwtService::class),
                    tokenStorage: $c->get(TokenStorageInterface::class),
                    rateLimiter: $c->get(RateLimiterInterface::class),
                    twoFactor: $c->get(TotpProvider::class),
                    events: $c->has(EventDispatcherInterface::class)
                        ? $c->get(EventDispatcherInterface::class) : null,
                );
            },

            /* Auth Manager (multi-guard) */
            AuthManager::class => static function ($c): AuthManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $defaultGuard = $mlc->getString('auth.default_guard', 'jwt') ?? 'jwt';
                $manager = new AuthManager($defaultGuard);

                // Register JWT guard
                $manager->register('jwt', new JwtGuard(
                    jwt: $c->get(JwtService::class),
                    users: $c->get(UserProviderInterface::class),
                    tokenStorage: $c->get(TokenStorageInterface::class),
                ));

                // Register Session guard if session manager is available
                if ($c->has(\MonkeysLegion\Session\SessionManager::class)) {
                    $manager->register('session', new SessionGuard(
                        session: $c->get(\MonkeysLegion\Session\SessionManager::class),
                        users: $c->get(UserProviderInterface::class),
                    ));
                }

                return $manager;
            },

            /* Gate */
            Gate::class => fn(): Gate => new Gate(),

            /* Authentication Middleware */
            AuthenticationMiddleware::class => static function ($c): AuthenticationMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthenticationMiddleware(
                    manager: $c->get(AuthManager::class),
                    responseFactory: $c->get(ResponseFactoryInterface::class),
                    defaultGuard: $mlc->getString('auth.default_guard', 'jwt') ?? 'jwt',
                );
            },

            /* Authorization Middleware */
            AuthorizationMiddleware::class => fn($c): AuthorizationMiddleware => new AuthorizationMiddleware(
                gate: $c->get(Gate::class),
            ),

            /* Auth Rate Limit Middleware */
            AuthRateLimitMiddleware::class => static function ($c): AuthRateLimitMiddleware {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthRateLimitMiddleware(
                    limiter: $c->get(RateLimiterInterface::class),
                    maxAttempts: $mlc->getInt('auth.rate_limit.max_attempts', 60) ?? 60,
                    decaySeconds: $mlc->getInt('auth.rate_limit.lockout_seconds', 60) ?? 60,
                );
            },
        ];
    }
}
