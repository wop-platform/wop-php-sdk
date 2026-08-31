<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F6/D10 — L2 线上信封 JSON：{"encrypted":"<base64url>"}（与网关 CryptoFilter 线上契约一致）。
 * b64url 字母表（A-Za-z0-9-_）无需 JSON 转义；提取容忍未知字段。
 */
final class EncryptedEnvelope
{
    /** 工具类禁实例化。 */
    private function __construct()
    {
    }

    /** 将密文（base64url 无填充）包裹为线上体。 */
    public static function wrap(string $cipherB64Url): string
    {
        return '{"encrypted":"' . $cipherB64Url . '"}';
    }

    /**
     * 从线上体提取 encrypted 密文字段（容忍未知字段）。
     * 非法 JSON / 非对象 / 缺字段 / 非字符串值 / 空串抛 WopException（协议类，语义明确）。
     */
    public static function extract(string $wireBody): string
    {
        try {
            $decoded = \json_decode($wireBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new WopException('L2 信封须为 JSON 对象');
        }
        if (!\is_array($decoded)) {
            throw new WopException('L2 信封须为 JSON 对象');
        }
        // PHP assoc 解码下 [] 既可能是 {} 也可能是空数组——非空 list（如 ["x"]）必非对象
        if ($decoded !== [] && \array_is_list($decoded)) {
            throw new WopException('L2 信封须为 JSON 对象');
        }
        if (!\array_key_exists('encrypted', $decoded)) {
            throw new WopException('L2 信封缺少 encrypted 字段');
        }
        $value = $decoded['encrypted'];
        if (!\is_string($value) || $value === '') {
            throw new WopException('L2 信封 encrypted 字段须为非空字符串');
        }
        return $value;
    }
}
