<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F4/D2/I5 — x-wop-content-digest：`<alg> 恰一空格 小写hex>`。
 * 标签与套件族强耦合（sha-256 仅 RSA 族）；多余空白拒绝而非容忍。
 */
final class ContentDigest
{
    private const LABEL_SHA256 = 'sha-256';

    /** 工具类禁实例化。 */
    private function __construct()
    {
    }

    /** SHA-256 摘要 → 64 字符小写 hex。 */
    public static function sha256Hex(string $bytes): string
    {
        return \hash('sha256', $bytes);
    }

    /**
     * 按套件族组装 digest 头（RSA 族 → sha-256）。
     */
    public static function build(string $wireBytes, Suite $suite): string
    {
        return $suite->digestLabel . ' ' . self::sha256Hex($wireBytes);
    }

    /**
     * 格式 + 族校验（D2/I5）：结构非法或跨族 → WopException（语义明确）；合法 → true。
     */
    public static function validate(string $headerValue, ?Suite $suite = null): bool
    {
        $parts = \explode(' ', $headerValue);
        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new WopException('x-wop-content-digest 格式错误（应为 <alg> 恰一空格 <hex>）: ' . $headerValue);
        }
        [$label, $hex] = $parts;
        $expectedLabel = $suite?->digestLabel ?? self::LABEL_SHA256;
        $allowed = $suite === null ? [self::LABEL_SHA256] : [$expectedLabel];
        if (!\in_array($label, $allowed, true)) {
            throw new WopException('x-wop-content-digest 算法标签与套件族不符: ' . $label);
        }
        if (!\ctype_xdigit($hex) || \strtolower($hex) !== $hex || \strlen($hex) !== 64) {
            throw new WopException('x-wop-content-digest 摘要格式错误（须 64 位小写 hex）: ' . $hex);
        }
        return true;
    }

    /**
     * 摘要对象 = 线上原始报文字节（D2）：校验 wire 字节与头一致。
     */
    public static function matches(string $headerValue, string $wireBytes): bool
    {
        if ($headerValue === '') {
            return false;
        }
        try {
            self::validate($headerValue);
        } catch (WopException) {
            return false;
        }
        [, $hex] = \explode(' ', $headerValue);
        return \hash_equals($hex, self::sha256Hex($wireBytes));
    }
}
