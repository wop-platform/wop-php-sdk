<?php

declare(strict_types=1);

namespace Wop\Sdk;

use phpseclib3\Crypt\RSA;

/**
 * spec:F3 — SHA256withRSA（RSASSA-PKCS1 v1.5），phpseclib≥3。
 * 密钥入参：PEM 或 Base64 单行（RSA=SPKI/PKCS8，D12）；解析结果进程内缓存。
 */
final class RsaSigner
{
    /** @var array<string, RSA\PrivateKey> */
    private static array $privateCache = [];

    /** @var array<string, RSA\PublicKey> */
    private static array $publicCache = [];

    /** 工具类禁实例化。 */
    private function __construct()
    {
    }

    /**
     * 加签，返回 base64url 无填充（RSA3072 恒 512 字符 / RSA4096 恒 683 字符）。
     */
    public static function sign(string $canonicalRequest, string $privateKey): string
    {
        $key = self::privateKey($privateKey);
        return Base64Url::encode($key->sign($canonicalRequest));
    }

    /**
     * 验签：数据/签名/公钥任一非法一律 false（不区分细节，I7）。
     */
    public static function verify(string $canonicalRequest, string $signatureB64u, string $publicKey): bool
    {
        try {
            $signature = Base64Url::decode($signatureB64u);
            return self::publicKey($publicKey)->verify($canonicalRequest, $signature);
        } catch (WopException) {
            return false;
        }
    }

    /** 私钥解析（PKCS1 v1.5 签名模式 + 进程内缓存）；失败包 WopException。 */
    private static function privateKey(string $material): RSA\PrivateKey
    {
        $cached = self::$privateCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)->withPadding(RSA::SIGNATURE_PKCS1);
        } catch (\Throwable $e) {
            throw new WopException('RSA 私钥解析失败（应为 PKCS8 PEM 或 Base64）: ' . $e->getMessage(), 0, $e);
        }
        return self::$privateCache[$material] = $key;
    }

    /** 公钥解析（PKCS1 v1.5 验签模式 + 进程内缓存）；失败包 WopException。 */
    private static function publicKey(string $material): RSA\PublicKey
    {
        $cached = self::$publicCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)->withPadding(RSA::SIGNATURE_PKCS1);
        } catch (\Throwable $e) {
            throw new WopException('RSA 公钥解析失败（应为 SPKI PEM 或 Base64）: ' . $e->getMessage(), 0, $e);
        }
        return self::$publicCache[$material] = $key;
    }
}
