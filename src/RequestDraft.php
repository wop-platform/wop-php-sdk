<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * 出向请求草稿：协议核心产出（headers + wireBody），零网络 IO；
 * 商户自带 HTTP 栈时直接消费本对象。
 */
final class RequestDraft
{
    /**
     * @param array<string, string> $headers 已含全部协议头（appkey/timestamp/nonce/digest/encrypt/sign）
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $headers,
        public readonly string $wireBody,
    ) {
    }

    /**
     * 大小写不敏感取头；缺席返回 null。
     */
    public function header(string $name): ?string
    {
        foreach ($this->headers as $key => $value) {
            if (\strcasecmp($key, $name) === 0) {
                return $value;
            }
        }
        return null;
    }
}
