<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F3 — 结构化 x-wop-sign：`<securityReq> v1/<expiredSeconds>/<signedHeaders>/<signature>`。
 * 严格解析（对齐网关 SignHeaderParser）：段数/协议版本/expiredSeconds 范围/signedHeaders 非空/signature 非空。
 */
final class SignHeader
{
    public const PROTOCOL_VERSION = 'v1';
    public const EXPIRED_SECONDS_MAX = 86400;

    /**
     * @param list<string> $signedHeaders
     */
    public function __construct(
        public readonly string $securityReq,
        public readonly string $protocolVersion,
        public readonly int $expiredSeconds,
        public readonly array $signedHeaders,
        public readonly string $signature,
    ) {
    }

    /**
     * @throws WopException 解析类错误（语义明确）
     */
    public static function parse(string $header): self
    {
        $trimmed = \trim($header);
        if ($trimmed === '') {
            throw new WopException('缺少 x-wop-sign');
        }
        $sp = \strpos($trimmed, ' ');
        if ($sp === false || $sp <= 0) {
            throw new WopException('x-wop-sign 格式错误：缺少 securityReq 与 authString 的空格分隔');
        }
        $securityReq = \substr($trimmed, 0, $sp);
        // 签名为 base64url（无 '/'），按 4 段拆分安全
        $seg = \explode('/', \trim(\substr($trimmed, $sp + 1)), 4);
        if (\count($seg) !== 4) {
            throw new WopException('x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature>');
        }
        if ($seg[0] !== self::PROTOCOL_VERSION) {
            throw new WopException('不支持的签名协议版本: ' . $seg[0]);
        }
        $expiredSeconds = self::parseExpiredSeconds($seg[1]);
        $signedHeaders = self::parseSignedHeaders($seg[2]);
        if (\trim($seg[3]) === '') {
            throw new WopException('signature 为空');
        }
        return new self($securityReq, $seg[0], $expiredSeconds, $signedHeaders, $seg[3]);
    }

    /**
     * 组装结构化头（出向加签用）。
     *
     * @param list<string> $signedHeaders
     */
    public static function build(string $securityReq, int $expiredSeconds, array $signedHeaders, string $signature): string
    {
        return $securityReq . ' ' . self::PROTOCOL_VERSION . '/' . $expiredSeconds
            . '/' . \implode(';', $signedHeaders) . '/' . $signature;
    }

    /**
     * 宽松提取 securityReq（头缺失/空白返回 null；合法性由 Suite::parse 校验）。
     */
    public static function tryExtractSecurityReq(?string $header): ?string
    {
        if ($header === null || \trim($header) === '') {
            return null;
        }
        $trimmed = \trim($header);
        $sp = \strpos($trimmed, ' ');
        return $sp === false ? $trimmed : \substr($trimmed, 0, $sp);
    }

    private static function parseExpiredSeconds(string $raw): int
    {
        if (!\ctype_digit($raw)) {
            throw new WopException('expiredSeconds 非法: ' . $raw);
        }
        $value = (int) $raw;
        if ($value <= 0 || $value > self::EXPIRED_SECONDS_MAX) {
            throw new WopException('expiredSeconds 超出允许范围 (0, ' . self::EXPIRED_SECONDS_MAX . ']');
        }
        return $value;
    }

    /** @return list<string> */
    private static function parseSignedHeaders(string $raw): array
    {
        $names = [];
        foreach (\explode(';', $raw) as $piece) {
            $name = \strtolower(\trim($piece));
            if ($name !== '') {
                $names[] = $name;
            }
        }
        if ($names === []) {
            throw new WopException('signedHeaders 为空');
        }
        return $names;
    }
}
