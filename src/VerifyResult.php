<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * 平台报文校验结果：ok=false 时 reason 为对外文案（验签/解密失败模糊，I7）；
 * L2 成功时 plaintext 为解密明文，L0 成功时为原样 body。
 */
final class VerifyResult
{
    private function __construct(
        public readonly bool $ok,
        public readonly ?string $plaintext,
        public readonly ?string $reason,
    ) {
    }

    public static function ok(string $plaintext): self
    {
        return new self(true, $plaintext, null);
    }

    public static function fail(string $reason): self
    {
        return new self(false, null, $reason);
    }
}
