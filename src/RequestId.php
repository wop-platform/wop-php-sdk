<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * 商户请求标识（wop-specs 附录 I：x-wop-request-id 透传头）。
 *
 * - I1：唯一出向可选透传头，恒不入签（签名落盘后写入）；
 * - I2：构造即校验——trim 前按原值扫描控制字符（< 0x20 或 == 0x7F，含 CR/LF/NUL/DEL，
 *   防头注入）、trim（G2 TrimAll 同集：空格、\t、\n、\x0B、\f、\r；不用 trim() 的
 *   Unicode 空白超集）后为空视为未设置、UTF-8 字节 > 128 拒（网关 header 缓冲按字节计）；
 * - I3：未传/空白 → 缺省生成 UUID 去连字符（小写 32 hex，v4 语义），最终头恒存在。
 */
final class RequestId
{
    /** 附录 I/I2 trim 集 = G2 TrimAll 空白类。 */
    private const TRIM_CHARS = " \t\n\x0B\f\r";

    /** 缺省生成器（可整体替换——测试确定性锚，与 random 注入同级）。 */
    public static ?\Closure $generator = null;

    /** 值语义约束（CWE-532）：须为不含个人数据的不透明关联标识。 */
    public static function generate(): string
    {
        if (self::$generator !== null) {
            return (self::$generator)();
        }
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40); // version 4
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80); // RFC 4122 variant
        return bin2hex($b);
    }

    /**
     * 校验并归一化（附录 I/I2）。
     *
     * @return string|null trim 后上行值；null = 未设置（调用方走缺省生成）
     *
     * @throws WopException configuration 类（控制字符 / 超长）
     */
    public static function resolve(?string $raw): ?string
    {
        if ($raw === null || $raw === '') {
            return null;
        }
        $chars = count_chars($raw, 1);
        foreach ($chars as $byte => $count) {
            if ($byte < 0x20 || $byte === 0x7F) {
                throw WopException::configuration("requestId 含控制字符（防头注入）: {$byte}");
            }
        }
        $trimmed = trim($raw, self::TRIM_CHARS);
        if ($trimmed === '') {
            return null;
        }
        $utf8Len = strlen($trimmed);
        if ($utf8Len > 128) {
            throw WopException::configuration("requestId UTF-8 字节长度不能超过 128（实际 {$utf8Len}）");
        }
        return $trimmed;
    }
}
