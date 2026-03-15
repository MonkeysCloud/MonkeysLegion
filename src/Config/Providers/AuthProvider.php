<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Auth\Contract\RateLimiterInterface;
use MonkeysLegion\Auth\Contract\TokenStorageInterface;
use MonkeysLegion\Auth\Contract\UserProviderInterface;
use MonkeysLegion\Auth\Middleware\AuthenticationMiddleware;
use MonkeysLegion\Auth\Middleware\AuthorizationMiddleware;
use MonkeysLegion\Auth\Middleware\RateLimitMiddleware as AuthRateLimitMiddleware;
use MonkeysLegion\Auth\OAuth\GitHubProvider;
use MonkeysLegion\Auth\OAuth\GoogleProvider;
use MonkeysLegion\Auth\OAuth\OAuthService;
use MonkeysLegion\Auth\Policy\Gate;
use MonkeysLegion\Auth\RBAC\PermissionChecker;
use MonkeysLegion\Auth\RBAC\RbacService;
use MonkeysLegion\Auth\RBAC\RoleRegistry;
use MonkeysLegion\Auth\RateLimit\CacheRateLimiter;
use MonkeysLegion\Auth\RateLimit\InMemoryRateLimiter;
use MonkeysLegion\Auth\RateLimit\RedisRateLimiter;
use MonkeysLegion\Auth\Service\AuthorizationService;
use MonkeysLegion\Auth\Service\AuthService;
use MonkeysLegion\Auth\Service\EmailVerificationService;
use MonkeysLegion\Auth\Service\JwtService;
use MonkeysLegion\Auth\Service\PasswordHasher;
use MonkeysLegion\Auth\Service\PasswordResetService;
use MonkeysLegion\Auth\Service\RedisTokenStorage;
use MonkeysLegion\Auth\Service\TwoFactorService;
use MonkeysLegion\Auth\Storage\InMemoryTokenStorage;
use MonkeysLegion\Auth\TwoFactor\TotpProvider;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Framework\Auth\DatabaseUserProvider;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\SimpleCache\CacheInterface;

final class AuthProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Password Hasher */
            PasswordHasher::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $algorithm = match ($mlc->get('auth.password.algorithm', 'default')) {
                    'bcrypt' => PASSWORD_BCRYPT,
                    'argon2id' => PASSWORD_ARGON2ID,
                    default => PASSWORD_DEFAULT,
                };

                return new PasswordHasher(
                    algorithm: $algorithm,
                    cost: (int) $mlc->get('auth.password.cost', 12)
                );
            },

            /* JWT Service */
            JwtService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new JwtService(
                    secret: (string) $mlc->get('auth.jwt_secret', ''),
                    accessTtl: (int) $mlc->get('auth.access_ttl', 1800),
                    refreshTtl: (int) $mlc->get('auth.refresh_ttl', 604800),
                    leeway: (int) $mlc->get('auth.jwt_leeway', 60),
                    issuer: $mlc->get('auth.issuer', null),
                    audience: $mlc->get('auth.audience', null),
                );
            },

            /* Rate Limiter (Auth Package) */
            RateLimiterInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driver = $mlc->get('auth.rate_limit.driver', 'cache');

                return match ($driver) {
                    'redis' => new RedisRateLimiter($c->get(\Redis::class)),
                    'cache' => new CacheRateLimiter($c->get(CacheInterface::class)),
                    default => new InMemoryRateLimiter(),
                };
            },

            /* User Provider */
            UserProviderInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new DatabaseUserProvider(
                    connection: $c->get(ConnectionInterface::class),
                    table: $mlc->get('auth.users.table', 'users'),
                    modelClass: $mlc->get('auth.users.model', 'App\\Entity\\User'),
                );
            },

            /* Token Storage */
            TokenStorageInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driver = $mlc->get('auth.token_storage.driver', 'memory');

                return match ($driver) {
                    'redis' => new RedisTokenStorage(
                        $c->get(\Redis::class),
                        $mlc->get('auth.token_storage.prefix', 'auth:')
                    ),
                    default => new InMemoryTokenStorage(),
                };
            },

            /* Core Auth Service */
            AuthService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthService(
                    users: $c->get(UserProviderInterface::class),
                    hasher: $c->get(PasswordHasher::class),
                    jwt: $c->get(JwtService::class),
                    tokenStorage: $c->get(TokenStorageInterface::class),
                    rateLimiter: $mlc->get('auth.rate_limit.enabled', true)
                        ? $c->get(RateLimiterInterface::class)
                        : null,
                    events: $c->get(EventDispatcherInterface::class),
                );
            },

            /* Two-Factor Authentication */
            TotpProvider::class => fn() => new TotpProvider(),

            TwoFactorService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new TwoFactorService(
                    provider: $c->get(TotpProvider::class),
                    events: $c->get(EventDispatcherInterface::class),
                    issuer: $mlc->get('auth.two_factor.issuer', 'MonkeysLegion'),
                );
            },

            /* RBAC */
            RoleRegistry::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $registry = new RoleRegistry();

                $roles = $mlc->get('rbac.roles', []);
                if (!empty($roles)) {
                    $registry->registerFromConfig($roles);
                }

                return $registry;
            },

            PermissionChecker::class => fn($c) => new PermissionChecker(
                $c->get(RoleRegistry::class)
            ),

            RbacService::class => fn($c) => new RbacService(
                $c->get(ConnectionInterface::class)->pdo()
            ),

            /* Authorization Gate & Service */
            Gate::class => static function ($c) {
                return new Gate();
            },

            AuthorizationService::class => fn($c) => new AuthorizationService(
                $c->get(PermissionChecker::class)
            ),

            /* OAuth2 Service */
            OAuthService::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $oauth = new OAuthService(
                    pdo: $c->get(ConnectionInterface::class)->pdo(),
                    jwt: $c->get(JwtService::class),
                    users: $c->get(UserProviderInterface::class),
                );

                if ($mlc->get('oauth.google.enabled', false)) {
                    $baseUrl = $mlc->get('app.url', '');
                    $oauth->registerProvider(new GoogleProvider(
                        clientId: $mlc->get('oauth.google.client_id', ''),
                        clientSecret: $mlc->get('oauth.google.client_secret', ''),
                        redirectUri: $baseUrl . $mlc->get('oauth.google.redirect_uri', '/oauth/google/callback'),
                    ));
                }

                if ($mlc->get('oauth.github.enabled', false)) {
                    $baseUrl = $mlc->get('app.url', '');
                    $oauth->registerProvider(new GitHubProvider(
                        clientId: $mlc->get('oauth.github.client_id', ''),
                        clientSecret: $mlc->get('oauth.github.client_secret', ''),
                        redirectUri: $baseUrl . $mlc->get('oauth.github.redirect_uri', '/oauth/github/callback'),
                    ));
                }

                return $oauth;
            },

            /* Password Reset Service */
            PasswordResetService::class => fn($c) => new PasswordResetService(
                users: $c->get(UserProviderInterface::class),
                hasher: $c->get(PasswordHasher::class),
                jwt: $c->get(JwtService::class),
                events: $c->get(EventDispatcherInterface::class),
            ),

            /* Email Verification Service */
            EmailVerificationService::class => fn($c) => new EmailVerificationService(
                users: $c->get(UserProviderInterface::class),
                jwt: $c->get(JwtService::class),
                events: $c->get(EventDispatcherInterface::class),
            ),

            /* Authentication Middleware */
            AuthenticationMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthenticationMiddleware(
                    auth: $c->get(AuthService::class),
                    users: $c->get(UserProviderInterface::class),
                    publicPaths: $mlc->get('auth.public_paths', []),
                    responseFactory: function (\Throwable $e) use ($c) {
                        return $c->get(ResponseFactoryInterface::class)
                            ->createResponse(401)
                            ->withHeader('Content-Type', 'application/json');
                    },
                );
            },

            /* Authorization Middleware */
            AuthorizationMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                return new AuthorizationMiddleware(
                    authorization: $c->get(AuthorizationService::class),
                    permissions: $c->get(PermissionChecker::class),
                    publicPaths: $mlc->get('auth.public_paths', []),
                    responseFactory: function (\Throwable $e) use ($c) {
                        $code = match (true) {
                            $e instanceof \MonkeysLegion\Auth\Exception\UnauthorizedException => 401,
                            $e instanceof \MonkeysLegion\Auth\Exception\ForbiddenException => 403,
                            default => 500,
                        };

                        return $c->get(ResponseFactoryInterface::class)
                            ->createResponse($code)
                            ->withHeader('Content-Type', 'application/json');
                    },
                );
            },

            /* Auth Rate Limit Middleware */
            AuthRateLimitMiddleware::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new AuthRateLimitMiddleware(
                    limiter: $c->get(RateLimiterInterface::class),
                    defaultMaxAttempts: (int) $mlc->get('auth.rate_limit.max_attempts', 60),
                    defaultDecaySeconds: (int) $mlc->get('auth.rate_limit.lockout_seconds', 60),
                    responseFactory: $c->get(ResponseFactoryInterface::class),
                );
            },
        ];
    }
}
