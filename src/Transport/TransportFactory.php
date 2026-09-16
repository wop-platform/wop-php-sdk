<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

use Wop\Sdk\WopException;

/** 默认传输发现（K18 P0：core 内置 curl 适配器）。 */
final class TransportFactory
{
    private function __construct()
    {
    }

    public static function discover(): TransportInterface
    {
        if (!extension_loaded('curl')) {
            throw WopException::configuration(
                '未找到可用传输（ext-curl 未安装）；请启用 ext-curl 或构造注入 GuzzleTransport'
            );
        }
        return new CurlTransport();
    }
}
