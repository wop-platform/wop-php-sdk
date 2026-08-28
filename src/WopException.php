<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * SDK 统一异常：配置/解析/协议类错误语义明确（10.2 错误分类总表）；
 * 验签与解密失败的对外模糊化由 VerifyResult.reason 承担（I7），不通过异常泄露细节。
 */
class WopException extends \RuntimeException
{
}
