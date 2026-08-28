<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

/**
 * spec:Q1 — 可插拔 HTTP 适配层：协议核心产 RequestDraft，传输由本接口实现。
 */
interface TransportInterface
{
    /**
     * 发送请求并返回响应。
     *
     * @param list<string> $headers 形如 "Name: value" 的头行
     * @throws \Wop\Sdk\WopException 传输失败
     */
    public function send(string $method, string $url, array $headers, string $body): TransportResponse;
}
