<?php

declare(strict_types=1);

namespace Wop\Sdk\Config;

/**
 * HTTP 客户端全局设置（§3.3 httpClient 对象，不可变）。
 */
final class HttpClientSettings
{
    public const DEFAULT_CONNECT_TIMEOUT = 10_000;
    public const DEFAULT_READ_TIMEOUT = 30_000;
    public const DEFAULT_MAX_RETRY_COUNT = 3;

    public function __construct(
        public readonly int $connectTimeout,
        public readonly int $readTimeout,
        public readonly int $maxRetryCount,
    ) {
    }

    /** 默认超时与重试上限。 */
    public static function defaults(): self
    {
        return new self(self::DEFAULT_CONNECT_TIMEOUT, self::DEFAULT_READ_TIMEOUT, self::DEFAULT_MAX_RETRY_COUNT);
    }
}
