<?php

declare(strict_types=1);

namespace Wop\Sdk\Config;

use phpseclib3\Crypt\RSA;
use Wop\Sdk\Suite;
use Wop\Sdk\WopException;

/** §3.4 语义校验与字段归一化。 */
final class ConfigValidator
{
    private function __construct()
    {
    }

    public static function validateAndNormalize(WopSdkConfig $raw): WopSdkConfig
    {
        if ($raw->appKey === '' || trim($raw->appKey) === '') {
            throw WopException::configuration('配置文件缺少必填项: appKey');
        }
        if ($raw->suite === '' || trim($raw->suite) === '') {
            throw WopException::configuration('配置文件缺少必填项: suite');
        }
        if ($raw->merchantPrivateKey === '' || trim($raw->merchantPrivateKey) === '') {
            throw WopException::configuration('配置文件缺少必填项: merchantPrivateKey');
        }
        if ($raw->platformPublicKey === '' || trim($raw->platformPublicKey) === '') {
            throw WopException::configuration('配置文件缺少必填项: platformPublicKey');
        }
        if ($raw->serverRoot === '' || trim($raw->serverRoot) === '') {
            throw WopException::configuration('配置文件缺少必填项: serverRoot');
        }
        if ($raw->expiredSeconds <= 0) {
            throw WopException::configuration('expiredSeconds 须为正整数');
        }

        try {
            $suite = Suite::parse($raw->suite);
        } catch (WopException $e) {
            throw WopException::configuration('不支持的算法套件: ' . $raw->suite, $e);
        }

        self::validateKeys($raw->merchantPrivateKey, $raw->platformPublicKey, $suite);

        $serverRoot = self::validateGatewayUrl($raw->serverRoot, 'serverRoot');
        $backups = [];
        foreach ($raw->backupServerRoots as $index => $value) {
            $backups[] = self::validateGatewayUrl($value, 'backupServerRoots[' . ($index + 1) . ']');
        }

        $http = $raw->httpClient;
        if ($http->connectTimeout <= 0 || $http->readTimeout <= 0 || $http->maxRetryCount < 0) {
            throw WopException::configuration('配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负');
        }

        return new WopSdkConfig(
            trim($raw->appKey),
            trim($raw->suite),
            trim($raw->merchantPrivateKey),
            trim($raw->platformPublicKey),
            $serverRoot,
            $backups,
            $raw->expiredSeconds,
            $http,
            $raw->transport,
        );
    }

    /** K20：HTTPS 绝对 URL，拒绝 query/fragment。 */
    public static function validateGatewayUrl(string $value, string $fieldName): string
    {
        $trimmed = trim($value);
        if ($trimmed === '') {
            throw WopException::configuration($fieldName . ' 不是合法 URL: ' . $value);
        }

        $parts = parse_url($trimmed);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw WopException::configuration($fieldName . ' 不是合法 URL: ' . $trimmed);
        }
        if (strcasecmp($parts['scheme'], 'https') !== 0) {
            throw WopException::configuration($fieldName . ' 须为 HTTPS 绝对 URL: ' . $trimmed);
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw WopException::configuration($fieldName . ' 不得含 query 或 fragment: ' . $trimmed);
        }

        $path = $parts['path'] ?? '';
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $normalized = 'https://' . strtolower($parts['host']) . $port . $path;
        if (str_ends_with($normalized, '/')) {
            $normalized = substr($normalized, 0, -1);
        }
        return $normalized;
    }

    /** §7.7 API path 语法校验。 */
    public static function validateApiPath(string $path): void
    {
        if ($path === '') {
            throw WopException::configuration('请求路径为空');
        }
        if (!str_starts_with($path, '/')) {
            throw WopException::configuration('path 须以 / 开头: ' . $path);
        }
        if (str_starts_with($path, '//')) {
            throw WopException::configuration('path 不得 // 开头: ' . $path);
        }
        if (str_contains($path, '?') || str_contains($path, '#')) {
            throw WopException::configuration('path 不得含 query 或 fragment: ' . $path);
        }
        if (stripos($path, 'http:') === 0 || stripos($path, 'https:') === 0) {
            throw WopException::configuration('path 不得为绝对 URL: ' . $path);
        }
    }

    /** §7.7 字符串拼接 serverRoot + path。 */
    public static function joinUrl(string $serverRoot, string $path): string
    {
        self::validateApiPath($path);
        $root = str_ends_with($serverRoot, '/') ? substr($serverRoot, 0, -1) : $serverRoot;
        $trimmedPath = ltrim($path, '/');
        return $root . '/' . $trimmedPath;
    }

    private static function validateKeys(string $merchantPrivateKey, string $platformPublicKey, Suite $suite): void
    {
        unset($suite);
        try {
            RSA::load($merchantPrivateKey)->withPadding(RSA::SIGNATURE_PKCS1);
            RSA::load($platformPublicKey)->withPadding(RSA::SIGNATURE_PKCS1);
        } catch (\Throwable $e) {
            throw WopException::configuration('密钥解析失败: ' . $e->getMessage(), $e);
        }
    }
}
