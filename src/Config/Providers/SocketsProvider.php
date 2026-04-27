<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Mlc\Config as MlcConfig;
use MonkeysLegion\Sockets\Contracts\BroadcasterInterface;
use MonkeysLegion\Sockets\Contracts\ConnectionRegistryInterface;
use MonkeysLegion\Sockets\Contracts\DriverInterface;
use MonkeysLegion\Sockets\Contracts\FormatterInterface;
use MonkeysLegion\Sockets\Broadcast\UnixBroadcaster;
use MonkeysLegion\Sockets\Handshake\AllowedOriginsMiddleware;
use MonkeysLegion\Sockets\Handshake\HandshakeNegotiator;
use MonkeysLegion\Sockets\Handshake\MiddlewarePipeline;
use MonkeysLegion\Sockets\Handshake\ResponseFactory;
use MonkeysLegion\Sockets\Protocol\JsonFormatter;
use MonkeysLegion\Sockets\Protocol\MsgPackFormatter;
use MonkeysLegion\Sockets\Registry\ConnectionRegistry;
use MonkeysLegion\Sockets\Server\WebSocketServer;
use MonkeysLegion\Sockets\Service\DriverFactory;
use MonkeysLegion\Sockets\Service\HeartbeatManager;
use MonkeysLegion\Sockets\Service\RoomManager;
use Psr\Container\ContainerInterface;

/**
 * WebSocket integration provider.
 *
 * Bridges the `monkeyslegion-sockets` package into the framework's DI system.
 * Registered in CLI context since WebSocket servers run from the CLI.
 */
final class SocketsProvider extends AbstractServiceProvider
{
    public function context(): string
    {
        return 'all';
    }

    public function getDefinitions(): array
    {
        return [
            // ── Registry ────────────────────────────────────────────
            ConnectionRegistryInterface::class => static fn(): ConnectionRegistryInterface => new ConnectionRegistry(),

            // ── Handshake Pipeline ──────────────────────────────────
            MiddlewarePipeline::class => static function (ContainerInterface $c): MiddlewarePipeline {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $pipeline = new MiddlewarePipeline();

                $origins = $mlc->get('sockets.security.allowed_origins');

                if (is_array($origins) && $origins !== []) {
                    $pipeline->add(new AllowedOriginsMiddleware($origins, new ResponseFactory()));
                }

                return $pipeline;
            },

            HandshakeNegotiator::class => static fn(ContainerInterface $c): HandshakeNegotiator => new HandshakeNegotiator(
                new ResponseFactory(),
                pipeline: $c->get(MiddlewarePipeline::class),
            ),

            // ── Driver Factory ──────────────────────────────────────
            DriverFactory::class => static function (ContainerInterface $c): DriverFactory {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $config = $mlc->get('sockets', []);

                return (new DriverFactory(is_array($config) ? $config : []))
                    ->setRegistry($c->get(ConnectionRegistryInterface::class))
                    ->setNegotiator($c->get(HandshakeNegotiator::class));
            },

            DriverInterface::class => static fn(ContainerInterface $c): DriverInterface => $c->get(DriverFactory::class)->make(),

            // ── Formatter ───────────────────────────────────────────
            FormatterInterface::class => static function (ContainerInterface $c): FormatterInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $format = $mlc->getString('sockets.formatter', 'json') ?? 'json';

                return $format === 'msgpack' ? new MsgPackFormatter() : new JsonFormatter();
            },

            // ── Heartbeat Manager ───────────────────────────────────
            HeartbeatManager::class => static function (ContainerInterface $c): HeartbeatManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new HeartbeatManager(
                    registry: $c->get(ConnectionRegistryInterface::class),
                    idleTimeout: $mlc->getInt('sockets.options.idle_timeout', 60) ?? 60,
                    pingInterval: $mlc->getInt('sockets.options.ping_interval', 30) ?? 30,
                );
            },

            // ── Broadcaster ─────────────────────────────────────────
            BroadcasterInterface::class => static function (ContainerInterface $c): BroadcasterInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);
                $socketPath = $mlc->getString('sockets.unix.path', '/tmp/ml_sockets.sock') ?? '/tmp/ml_sockets.sock';

                return new UnixBroadcaster($socketPath);
            },

            // ── Room Manager ────────────────────────────────────────
            RoomManager::class => static fn(ContainerInterface $c): RoomManager => new RoomManager(
                registry: $c->get(ConnectionRegistryInterface::class),
                broadcaster: $c->get(BroadcasterInterface::class),
            ),

            // ── WebSocket Server (Master Orchestrator) ──────────────
            WebSocketServer::class => static fn(ContainerInterface $c): WebSocketServer => (new WebSocketServer(
                registry: $c->get(ConnectionRegistryInterface::class),
                broadcaster: $c->get(BroadcasterInterface::class),
                formatter: $c->get(FormatterInterface::class),
            ))->setDriver($c->get(DriverInterface::class)),
        ];
    }
}
