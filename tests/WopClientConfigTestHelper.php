<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\Config\WopConfigLoader;
use Wop\Sdk\WopClient;

/** 测试辅助：重置一站式入口全局状态。 */
final class WopClientConfigTestHelper
{
    private function __construct()
    {
    }

    public static function resetDefault(): void
    {
        WopConfigLoader::clearCache();
        WopClient::resetDefault();
    }
}
