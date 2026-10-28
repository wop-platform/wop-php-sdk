<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * ISV 子商户身份（ISV D-13：x-wop-sub-mch-id 头，值 = 子商户 plf_co_id）。
 *
 * - 仅接受可打印 ASCII（0x20..0x7E）：控制字符（CR/LF/NUL/DEL）防头注入，
 *   非 ASCII 在 HTTP 头编码下不可靠；
 * - trim 后为空 → 视为未设置（头缺席 = 应用自身身份，AC-20 零回归）；
 * - trim 后含内部空白 → 拒：网关 canonical 的 trimall 会折叠内部空白，而身份查询只做 trim，
 *   内部空白破坏签名与身份一一对应；
 * - trim 后长度 > 128 → 拒（ASCII 下 strlen 即字节数）。
 */
final class SubMchId
{
    /**
     * 校验并归一化。
     *
     * @return string|null trim 后上行值；null = 未设置（头缺席）
     *
     * @throws WopException configuration 类（非可打印 ASCII / 内部空白 / 超长）
     */
    public static function resolve(?string $raw): ?string
    {
        if ($raw === null || $raw === '') {
            return null;
        }
        // trim 前按原值逐字节扫描（与控制字符先拒、空白后 trim 的跨仓顺序一致）
        foreach (\array_keys(\count_chars($raw, 1)) as $byte) {
            if ($byte < 0x20 || $byte > 0x7e) {
                throw WopException::configuration("subMchId 须为可打印 ASCII（防头注入/签名歧义）: {$byte}");
            }
        }
        // 可打印 ASCII 已保证：trim 只会去掉首尾空格（0x20），与网关 trim 语义一致
        $trimmed = \trim($raw);
        if ($trimmed === '') {
            return null;
        }
        if (\str_contains($trimmed, ' ')) {
            throw WopException::configuration('subMchId 不能包含内部空白');
        }
        $length = \strlen($trimmed);
        if ($length > 128) {
            throw WopException::configuration("subMchId 长度不能超过 128（实际 {$length}）");
        }
        return $trimmed;
    }
}
