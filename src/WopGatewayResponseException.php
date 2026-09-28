<?php

declare(strict_types=1);

namespace Wop\Sdk;

/** 网关非 2xx 响应（§7.5）；携带 statusCode 与 body 快照，不进入验签。 */
final class WopGatewayResponseException extends WopException
{
        /** 携带状态码与响应体快照；消息不内嵌 body 全文（K5 防日志膨胀）。 */
    public function __construct(
        public readonly int $statusCode,
        public readonly string $body,
    ) {
        parent::__construct(
            'WOP 网关返回 HTTP ' . $statusCode . '（响应体 ' . strlen($body) . ' 字节）'
        );
    }
}
