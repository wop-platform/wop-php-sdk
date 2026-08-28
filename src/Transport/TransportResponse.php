<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

/**
 * 传输响应：状态码 / 头（大小写不敏感可查）/ body 字节串。
 */
final class TransportResponse
{
    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $statusCode,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function isSuccess(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

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
