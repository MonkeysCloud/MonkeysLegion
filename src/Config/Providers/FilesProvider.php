<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Files\Contracts\StorageInterface;
use MonkeysLegion\Files\Driver\LocalDriver;
use MonkeysLegion\Files\FilesManager;
use MonkeysLegion\Files\Image\ImageDriver;
use MonkeysLegion\Files\Image\ImageProcessor;
use MonkeysLegion\Files\Maintenance\GarbageCollector;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * File storage, upload management, and image processing provider.
 *
 * Uses the Files package's LocalDriver, FilesManager, ImageDriver enum.
 */
final class FilesProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            /* Default disk: local driver */
            StorageInterface::class => static function ($c): StorageInterface {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $root = base_path($mlc->getString('files.disks.local.root', 'storage/files') ?? 'storage/files');

                return new LocalDriver(basePath: $root);
            },

            /* Files Manager */
            FilesManager::class => static function ($c): FilesManager {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new FilesManager(
                    disks: ['local' => $c->get(StorageInterface::class)],
                    defaultDisk: $mlc->getString('files.default', 'local') ?? 'local',
                    logger: $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : new NullLogger(),
                );
            },

            /* Image Processor */
            ImageProcessor::class => static function ($c): ImageProcessor {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $driverName = $mlc->getString('files.image.driver', 'gd') ?? 'gd';
                $quality = $mlc->getInt('files.image.quality', 85) ?? 85;

                return new ImageProcessor(
                    driver: ImageDriver::from($driverName),
                    defaultQuality: $quality,
                );
            },

            /* Garbage Collector */
            GarbageCollector::class => static function ($c): GarbageCollector {
                return new GarbageCollector(
                    logger: $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : new NullLogger(),
                );
            },
        ];
    }
}
