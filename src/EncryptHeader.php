<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * x-wop-encrypt 指令：`<level>[;dek=<base64url(非对称包装(alg$key$iv))>]`。
 * level 仅 L0/L2。
 */
final class EncryptHeader
{
    public const LEVEL_L0 = 'L0';
    public const LEVEL_L2 = 'L2';

    private const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    /**
     * @param string $level 加密级别（L0 明文 / L2 信封）
     * @param string|null $dek L2 时的 DEK 载荷（base64url 包装），L0 为 null
     */
    public function __construct(
        public readonly string $level,
        public readonly ?string $dek,
    ) {
    }

    /** 是否为 L2 加密请求。 */
    public function isEncrypted(): bool
    {
        return \strcasecmp($this->level, self::LEVEL_L2) === 0;
    }

    /**
     * null/空视为 L0；level 非法抛 WopException。
     */
    public static function parse(?string $header): self
    {
        if ($header === null || \trim($header) === '') {
            return new self(self::LEVEL_L0, null);
        }
        $parts = \explode(';', $header);
        $level = \trim($parts[0]);
        self::validateLevel($level);
        $dek = null;
        foreach (\array_slice($parts, 1) as $part) {
            if (\strncasecmp(\trim($part), 'dek=', 4) === 0) {
                $dek = \trim(\substr(\trim($part), 4));
            }
        }
        // 密文段字符集前置校验（b64url 无填充，公开结构知识 → 协议类明确；与 Go 基线一致）
        if ($dek !== null && \strspn($dek, self::B64URL_CHARS) !== \strlen($dek)) {
            throw new WopException('x-wop-encrypt dek 段须为 base64url 无填充');
        }
        return new self(\strtoupper($level), $dek);
    }

    /** level 合法性校验（仅 L0/L2，大小写不敏感）；非法抛 WopException。 */
    public static function validateLevel(string $level): void
    {
        if (\strcasecmp($level, self::LEVEL_L0) === 0 || \strcasecmp($level, self::LEVEL_L2) === 0) {
            return;
        }
        throw new WopException('不支持的加密级别 level=' . $level . '，仅支持 L0/L2');
    }

    /** 组装线上头：L0 裸 level；L2 追加 `;dek=<载荷>`。 */
    public static function build(string $level, ?string $dek): string
    {
        return $dek === null ? $level : $level . ';dek=' . $dek;
    }
}
