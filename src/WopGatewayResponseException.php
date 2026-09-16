<?php

declare(strict_types=1);

namespace Wop\Sdk;

/** 网关非 2xx 响应（§7.5）；携带 statusCode 与 body 快照，不进入验签。 */
final class WopGatewayResponseException extends WopException
{
    public function __construct(
        public readonly int $statusCode,
        public readonly string $body,
    ) {
        parent::__construct(
            'WOP 网关返回 HTTP ' . $statusCode . '（响应体 ' . strlen($body) . ' 字节）'
        );
    }
}
