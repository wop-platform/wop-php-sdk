<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * SDK 配置（不可变）。
 *
 * appKey         商户应用标识
 * securityReq    算法套件（WOP-RSA3072-SHA256 / WOP-RSA4096-SHA256）
 * privateKey     己方私钥（出向加签 / 入向 DEK 解包；PKCS8 PEM 或 Base64 单行）
 * peerPublicKey  对端公钥（响应/回调验签 / DEK 包装；SPKI PEM 或 Base64 单行）
 */
final class WopConfig
{
    public readonly Suite $suite;

    public function __construct(
        public readonly string $appKey,
        string $securityReq,
        public readonly string $privateKey,
        public readonly string $peerPublicKey,
        public readonly ?string $gatewayBaseUrl = null,
    ) {
        $this->suite = Suite::parse($securityReq);
    }
}
