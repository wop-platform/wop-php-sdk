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

    /** 工具类禁实例化。 */
    private function __construct()
    {
    }

    /** 编码：标准 base64 转 URL 字母表（`+`/`/` → `-`/`_`）并去 `=` 填充。 */
    public static function encode(string $bytes): string
    {
        return \rtrim(\strtr(\base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * 严格解码：非法字符（含 `=`、`+`、`/`）、不可能长度（%4==1）与
     * 非规范尾随位抛 WopException（与 Go base64.RawURLEncoding.Strict() 对齐，RFC 4648 §3.5）。
     * 异常消息不携带原始输入（防 DEK 等密钥材料经日志泄露）。
     */
    public static function decode(string $text): string
    {
        $len = \strlen($text);
        if ($len % 4 === 1) {
            throw new WopException('base64url 串长度非法（%4==1）');
        }
        if (\strspn($text, self::ALPHABET) !== $len) {
            throw new WopException('base64url 串含非法字符（须无填充、URL 字母表）');
        }
        // 非规范尾随位显式校验：base64_decode(strict) 不检查尾随位（宽容收下 'ab'→'i'）。
        // %4==2（1 字节 → 2 字符，8 数据位）→ 尾字符低 4 位须为零；
        // %4==3（2 字节 → 3 字符，16 数据位）→ 尾字符低 2 位须为零
        $rem = $len % 4;
        if ($rem === 2 || $rem === 3) {
            $idx = self::decodeIndex($text[$len - 1]);
            $mask = $rem === 2 ? 0xF : 0x3;
            if (($idx & $mask) !== 0) {
                throw new WopException('base64url 串含非规范尾随位');
            }
        }
        // 预检（字符集 + 长度 + 尾随位）后 strict 解码必然成功
        return \base64_decode(\strtr($text, '-_', '+/'), true);
    }

    /** 单字符 → 6 位索引（尾随位预检用；调用前字符集已校验）。 */
    private static function decodeIndex(string $char): int
    {
        $o = \ord($char);
        if ($o >= 65 && $o <= 90) {
            return $o - 65; // A-Z
        }
        if ($o >= 97 && $o <= 122) {
            return $o - 97 + 26; // a-z
        }
        if ($o >= 48 && $o <= 57) {
            return $o - 48 + 52; // 0-9
        }
        return $o === 45 ? 62 : 63; // '-' else '_'
    }
}
