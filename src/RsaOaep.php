<?php

declare(strict_types=1);

namespace Wop\Sdk;

use phpseclib3\Crypt\RSA;

/**
 * spec:F5/D10/F2 — RSA-OAEP 显式双 SHA-256 + 空 label（DEK 包装）。
 * phpseclib OAEP 支持自定义 MGF1；openssl 扩展 OAEP 哈希写死与 MGF1 不匹配，不可用（B.1 注记）。
 */
final class RsaOaep
{
    /** @var array<string, RSA\PrivateKey> */
    private static array $privateCache = [];

    /** @var array<string, RSA\PublicKey> */
    private static array $publicCache = [];

    private function __construct()
    {
    }

    /**
     * 公钥包装，返回 base64url 无填充。
     */
    public static function wrap(string $plaintext, string $publicKey): string
    {
        return Base64Url::encode(self::publicKey($publicKey)->encrypt($plaintext));
    }

    /**
     * 私钥解包；失败（含 mgf1-sha1 陷阱密文、篡改）返回 null——失败细节对外模糊（I7）。
     */
    public static function unwrap(string $cipherB64u, string $privateKey): ?string
    {
        try {
            $cipher = Base64Url::decode($cipherB64u);
            return self::privateKey($privateKey)->decrypt($cipher);
        } catch (\Throwable) {
            return null;
        }
    }

    private static function privateKey(string $material): RSA\PrivateKey
    {
        $cached = self::$privateCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256')
                ->withMGFHash('sha256'); // F2 钉子：MGF1 显式 SHA-256（JCA 默认是 SHA-1）
        } catch (\Throwable $e) {
            throw new WopException('RSA 私钥解析失败: ' . $e->getMessage(), 0, $e);
        }
        return self::$privateCache[$material] = $key;
    }

    private static function publicKey(string $material): RSA\PublicKey
    {
        $cached = self::$publicCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256')
                ->withMGFHash('sha256');
        } catch (\Throwable $e) {
            throw new WopException('RSA 公钥解析失败: ' . $e->getMessage(), 0, $e);
        }
        return self::$publicCache[$material] = $key;
    }
}
