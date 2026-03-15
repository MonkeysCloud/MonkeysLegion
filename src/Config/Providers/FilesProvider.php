<?php

declare(strict_types=1);

namespace MonkeysLegion\Config\Providers;

use MonkeysLegion\Cache\CacheManager;
use MonkeysLegion\Database\Contracts\ConnectionInterface;
use MonkeysLegion\Files\Contracts\ChunkedUploadInterface;
use MonkeysLegion\Files\Contracts\StorageInterface;
use MonkeysLegion\Files\FilesManager;
use MonkeysLegion\Files\Image\ImageProcessor;
use MonkeysLegion\Files\Maintenance\GarbageCollector;
use MonkeysLegion\Files\RateLimit\UploadRateLimiter;
use MonkeysLegion\Files\Repository\FileRepository;
use MonkeysLegion\Files\Storage\LocalStorage;
use MonkeysLegion\Files\Upload\ChunkedUploadManager;
use MonkeysLegion\Mlc\Config as MlcConfig;
use Psr\Log\LoggerInterface;

final class FilesProvider extends AbstractServiceProvider
{
    public function getDefinitions(): array
    {
        return [
            StorageInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $diskConfig = $mlc->get('files.disks.local', [
                    'driver' => 'local',
                    'root' => base_path('storage/files'),
                    'visibility' => 'public',
                ]);

                return new LocalStorage(
                    basePath: $diskConfig['root'],
                    baseUrl: $diskConfig['url'] ?? '/storage/files',
                    directoryPermissions: $diskConfig['permissions']['dir'] ?? 0755,
                    filePermissions: $diskConfig['permissions']['file'] ?? 0644,
                    visibility: $diskConfig['visibility'],
                );
            },

            FilesManager::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                $manager = new FilesManager(
                    config: $mlc->get('files', []),
                    logger: $c->get(LoggerInterface::class),
                );

                $cacheConfig = require base_path('config/cache.php') ?? [];
                if (!empty($cacheConfig) && isset($cacheConfig['driver'])) {
                    $cacheManager = new CacheManager($cacheConfig);
                    $manager->setCache($cacheManager->store());
                }

                $manager->addDisk('local', $c->get(StorageInterface::class));

                if ($mlc->get('files.database.enabled', false)) {
                    $manager->setRepository($c->get(FileRepository::class));
                }

                return $manager;
            },

            ImageProcessor::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ImageProcessor(
                    driver: $mlc->get('files.image.driver', 'gd'),
                    quality: (int) $mlc->get('files.image.quality', 85),
                );
            },

            ChunkedUploadInterface::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new ChunkedUploadManager(
                    storage: $c->get(StorageInterface::class),
                    tempDir: $mlc->get('files.upload.temp_dir', sys_get_temp_dir() . '/ml-uploads'),
                    cache: (new CacheManager($mlc->get('cache', [])))->store(),
                    chunkSize: (int) $mlc->get('files.upload.chunk_size', 5 * 1024 * 1024),
                    uploadExpiry: (int) $mlc->get('files.upload.chunk_expiry', 86400),
                );
            },

            ChunkedUploadManager::class => fn($c) => $c->get(ChunkedUploadInterface::class),

            FileRepository::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new FileRepository(
                    connection: $c->get(ConnectionInterface::class),
                    tableName: $mlc->get('files.database.tables.files', 'ml_files'),
                    conversionsTable: $mlc->get('files.database.tables.conversions', 'ml_file_conversions'),
                    trackAccess: (bool) $mlc->get('files.database.track_access', true),
                    softDelete: (bool) $mlc->get('files.database.soft_delete', true),
                );
            },

            UploadRateLimiter::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new UploadRateLimiter(
                    cache: new CacheManager($mlc->get('cache', [])),
                    maxUploadsPerMinute: (int) $mlc->get('files.rate_limiting.uploads_per_minute', 10),
                    maxBytesPerHour: (int) $mlc->get('files.rate_limiting.bytes_per_hour', 104857600),
                    maxConcurrentUploads: (int) $mlc->get('files.rate_limiting.concurrent_uploads', 3),
                );
            },

            GarbageCollector::class => static function ($c) {
                /** @var MlcConfig $mlc */
                $mlc = $c->get(MlcConfig::class);

                return new GarbageCollector(
                    storage: $c->get(StorageInterface::class),
                    repository: $mlc->get('files.database.enabled', false)
                        ? $c->get(FileRepository::class)
                        : null,
                    config: [
                        'deleted_files_days' => (int) $mlc->get('files.garbage_collection.deleted_files_days', 30),
                        'incomplete_uploads_hours' => (int) $mlc->get('files.garbage_collection.incomplete_uploads_hours', 24),
                        'unused_conversions_days' => (int) $mlc->get('files.garbage_collection.unused_conversions_days', 7),
                    ],
                    logger: $c->get(LoggerInterface::class),
                );
            },
        ];
    }
}
