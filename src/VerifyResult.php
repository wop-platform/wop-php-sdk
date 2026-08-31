<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * 平台报文校验结果：ok=false 时 reason 为对外文案（验签/解密失败模糊，I7）；
 * L2 成功时 plaintext 为解密明文，L0 成功时为原样 body。
 */
final class VerifyResult
{
    /** 私有构造：仅经 ok()/fail() 工厂产出。 */
    private function __construct(
        public readonly bool $ok,
        public readonly ?string $plaintext,
        public readonly ?string $reason,
    ) {
    }

    /** 成功结果：ok=true + 明文（L2 解密后 / L0 原样）。 */
    public static function ok(string $plaintext): self
    {
        return new self(true, $plaintext, null);
    }

    /** 失败结果：ok=false + 对外文案（验签/解密类模糊，I7）。 */
    public static function fail(string $reason): self
    {
        return new self(false, null, $reason);
    }
}
