<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

use Wop\Sdk\WopException;

/** 默认传输发现（K18 P0：core 内置 curl 适配器）。 */
final class TransportFactory
{
        /** 私有构造：纯静态门。 */
    private function __construct()
    {
    }

        /** 传输发现（§7.2 K12/K18：curl 扩展缺席即 configuration，多实现歧义 fail-fast）。 */
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
