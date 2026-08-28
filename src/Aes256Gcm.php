<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F5/D10 — AES-256-GCM bulk 加密（L2 信封）：密钥 32B / IV 12B / tag 128b，
 * 线上密文 = ciphertext||tag 尾部拼接（openssl tag 独立出参，拼接在本层完成）。
 */
final class Aes256Gcm
{
    public const KEY_BYTES = 32;
    public const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    private function __construct()
    {
    }

    /**
     * 加密；未传 IV 时 CSPRNG 生成（I4：同一密钥下 IV 永不复用）。
     */
    public static function encrypt(string $plaintext, string $key, ?string $iv = null): AesGcmResult
    {
        self::assertKey($key);
        if ($iv === null) {
            $iv = \random_bytes(self::IV_BYTES);
        } elseif (\strlen($iv) !== self::IV_BYTES) {
            throw new WopException('IV 长度非法（须 12 字节）');
        }
        $tag = '';
        $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_BYTES);
        return new AesGcmResult($cipher . $tag, $iv);
    }

    /**
     * 解密（密文含尾拼 tag）；失败返回 null——对外模糊（I7）。
     */
    public static function decrypt(string $cipherTag, string $iv, string $key): ?string
    {
        self::assertKey($key);
        if (\strlen($iv) !== self::IV_BYTES || \strlen($cipherTag) < self::TAG_BYTES) {
            return null;
        }
        $body = \substr($cipherTag, 0, -self::TAG_BYTES);
        $tag = \substr($cipherTag, -self::TAG_BYTES);
        $plain = openssl_decrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $plain === false ? null : $plain;
    }

    private static function assertKey(string $key): void
    {
        if (\strlen($key) !== self::KEY_BYTES) {
            throw new WopException('AES-256 密钥长度非法（须 32 字节）');
        }
    }
}
