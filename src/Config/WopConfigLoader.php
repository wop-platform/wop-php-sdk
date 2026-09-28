<?php

declare(strict_types=1);

namespace Wop\Sdk\Config;

use Wop\Sdk\WopException;

/** 配置加载入口（§4，线程安全）。 */
final class WopConfigLoader
{
    public const CONFIG_FILE_ENV = 'WOP_SDK_CONFIG';
    public const CONFIG_FILE_OVERRIDE_ENV = 'WOP_SDK_CONFIG_FILE';
    private const CLASSPATH_PREFIX = 'classpath:';
    private const PACKAGED_CONFIG = 'config/wopSdkConfig.json';

    /** @var array<string, WopSdkConfig> */
    private static array $cache = [];

        /** 私有构造：纯静态门。 */
    private function __construct()
    {
    }

        /** 按 §4.2 自动发现并加载；同一位置缓存解析结果（K13 无自动失效）。 */
    public static function loadDefault(): WopSdkConfig
    {
        $discovery = self::discover();
        return self::loadCached($discovery['cacheKey'], $discovery['reader']);
    }

        /** 显式位置：pkg:/classpath: 前缀走打包资源，其余一律文件系统路径（K14）。 */
    public static function load(string $location): WopSdkConfig
    {
        if (str_starts_with($location, self::CLASSPATH_PREFIX)) {
            $resource = substr($location, strlen(self::CLASSPATH_PREFIX));
            return self::loadCached('classpath:' . $resource, static fn (): string => self::readClasspath($resource));
        }
        return self::loadPath($location);
    }

        /** 显式文件系统路径加载。 */
    public static function loadPath(string $path): WopSdkConfig
    {
        $normalized = str_replace('\\', '/', realpath($path) ?: $path);
        return self::loadCached('file:' . $normalized, static function () use ($path): string {
            if (!is_readable($path)) {
                throw WopException::configuration('配置文件不可读: ' . $path);
            }
            $content = file_get_contents($path);
            if ($content === false) {
                throw WopException::configuration('配置文件读取失败: ' . $path);
            }
            return $content;
        });
    }

        /** 清除加载缓存（测试/配置轮换编排，K13）。 */
    public static function clearCache(): void
    {
        self::$cache = [];
    }

    /** @param callable(): string $reader */
    private static function loadCached(string $key, callable $reader): WopSdkConfig
    {
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }
        $parsed = ConfigJsonParser::parse($reader());
        self::$cache[$key] = $parsed;
        return $parsed;
    }

    /** @return array{cacheKey: string, reader: callable(): string} */
    private static function discover(): array
    {
        $override = getenv(self::CONFIG_FILE_OVERRIDE_ENV);
        if (is_string($override) && trim($override) !== '') {
            return self::fileDiscovery(trim($override), true);
        }
        $env = getenv(self::CONFIG_FILE_ENV);
        if (is_string($env) && trim($env) !== '') {
            return self::fileDiscovery(trim($env), true);
        }

        $cwd = getcwd() ?: '.';
        $home = getenv('HOME') ?: getenv('USERPROFILE') ?: '';
        $candidates = [
            $cwd . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'wopSdkConfig.json',
            $cwd . DIRECTORY_SEPARATOR . 'wopSdkConfig.json',
        ];
        if ($home !== '') {
            $candidates[] = $home . DIRECTORY_SEPARATOR . '.wop' . DIRECTORY_SEPARATOR . 'wopSdkConfig.json';
        }
        foreach ($candidates as $candidate) {
            if (is_readable($candidate)) {
                return self::fileDiscovery($candidate, false);
            }
        }

        $packaged = self::packagedResourcePath(self::PACKAGED_CONFIG);
        if ($packaged !== null && is_readable($packaged)) {
            return self::fileDiscovery($packaged, false);
        }

        $expanded = array_merge($candidates, [$packaged ?? self::packagedResourcePath(self::PACKAGED_CONFIG) ?? self::PACKAGED_CONFIG]);
        throw WopException::configuration(
            '未找到可读配置文件，已尝试: ' . implode(', ', $expanded)
        );
    }

    /** @return array{cacheKey: string, reader: callable(): string} */
    private static function fileDiscovery(string $path, bool $explicit): array
    {
        $normalized = str_replace('\\', '/', realpath($path) ?: $path);
        return [
            'cacheKey' => 'file:' . $normalized,
            'reader' => static function () use ($path, $explicit, $normalized): string {
                if (!is_readable($path)) {
                    $message = $explicit
                        ? '显式配置文件不可读: ' . $normalized
                        : '配置文件不可读: ' . $normalized;
                    throw WopException::configuration($message);
                }
                $content = file_get_contents($path);
                if ($content === false) {
                    throw WopException::configuration('配置文件读取失败: ' . $normalized);
                }
                return $content;
            },
        ];
    }

        /** 读打包资源（K6 兜底来源）。 */
    private static function readClasspath(string $resource): string
    {
        $path = self::packagedResourcePath($resource);
        if ($path === null || !is_readable($path)) {
            throw WopException::configuration('classpath 资源不存在: ' . $resource);
        }
        $content = file_get_contents($path);
        if ($content === false) {
            throw WopException::configuration('classpath 资源读取失败: ' . $resource);
        }
        return $content;
    }

        /** 识别打包资源前缀并归一化资源路径；非资源位置返回 null。 */
    private static function packagedResourcePath(string $resource): ?string
    {
        $root = dirname(__DIR__, 2);
        $candidate = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $resource);
        return is_file($candidate) ? $candidate : null;
    }
}
