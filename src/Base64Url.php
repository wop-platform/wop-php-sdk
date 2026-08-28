<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F7/D10 — 线上二进制编码：Base64URL 无填充，严格模式。
 * 服务端拒收带 `=` 的输入；解码同样拒绝标准字母表（`+`、`/`）。
 */
final class Base64Url
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    private function __construct()
    {
    }

    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * 严格解码：非法字符（含 `=`、`+`、`/`）与不可能长度（%4==1）抛 WopException。
     */
    public static function decode(string $text): string
    {
        $len = strlen($text);
        if ($len % 4 === 1) {
            throw new WopException('base64url 长度非法: ' . $text);
        }
        if (strspn($text, self::ALPHABET) !== $len) {
            throw new WopException('base64url 含非法字符: ' . $text);
        }
        $decoded = base64_decode(strtr($text, '-_', '+/'), true);
        if ($decoded === false) {
            throw new WopException('base64url 解码失败: ' . $text);
        }
        return $decoded;
    }
}
