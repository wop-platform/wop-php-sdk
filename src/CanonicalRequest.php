<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F2 — canonicalRequest 构造（5 段 `\n`；与网关 CanonicalRequestBuilder 逐字节对齐）。
 * header 值 Java-URLEncoder 语义：空格→%20、`+`→%2B、`;`→%3B、`=`→%3D；
 * 保留 `.` `-` `*` `_`；编码 `~` `!` `'` `(` `)`。
 */
final class CanonicalRequest
{
    private function __construct()
    {
    }

    /**
     * Java URLEncoder（UTF-8）+ 空格→%20 替换，与网关侧完全一致。
     */
    public static function urlencode(?string $text): string
    {
        if ($text === null || $text === '') {
            return '';
        }
        // rawurlencode：RFC3986，保留 A-Za-z0-9-._~，输出大写 hex
        $encoded = rawurlencode($text);
        // 对齐 Java URLEncoder 字母表差异：~ 需编码，* 需保留
        $encoded = str_replace('~', '%7E', $encoded);
        $encoded = str_replace('%2A', '*', $encoded);
        return $encoded;
    }

    /**
     * Trimall：去首尾空白，连续空白折叠为单个空格。
     */
    public static function trimall(?string $text): string
    {
        if ($text === null || $text === '') {
            return '';
        }
        return trim((string) preg_replace('/\s+/u', ' ', $text));
    }

    /**
     * 规范标头：名称 lowercase+Trimall+urlencode，值 Trimall+urlencode，
     * 名称 ASCII 升序，行间 `\n` 连接，尾行无 `\n`。
     *
     * @param array<string, string|null>|null $headers
     */
    public static function canonicalHeaders(?array $headers): string
    {
        if ($headers === null) {
            return '';
        }
        $sorted = [];
        foreach ($headers as $name => $value) {
            $sorted[strtolower(self::trimall((string) $name))] = self::trimall((string) ($value ?? ''));
        }
        uksort($sorted, strcmp(...));
        $lines = [];
        foreach ($sorted as $name => $value) {
            $lines[] = self::urlencode($name) . ':' . self::urlencode($value);
        }
        return implode("\n", $lines);
    }

    /**
     * 5 段组装：authString \n METHOD \n URI \n queryString \n canonicalHeaders。
     * null 段以空串参与（空行不可省）。
     */
    public static function build(
        ?string $authString,
        ?string $method,
        ?string $canonicalUri,
        ?string $queryString,
        ?string $canonicalHeaders
    ): string {
        return ($authString ?? '') . "\n"
            . strtoupper(trim((string) $method)) . "\n"
            . ($canonicalUri ?? '') . "\n"
            . ($queryString ?? '') . "\n"
            . ($canonicalHeaders ?? '');
    }
}
