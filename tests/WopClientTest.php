<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\WopClient;
use Wop\Sdk\WopConfig;
use Wop\Sdk\WopException;

/**
 * spec:A6 协议语义集成：D2 无 body 缺席 / I1 digest 入签 / F6 校验顺序 / I7 模糊化 / F9 防重放字段。
 * 商户→平台用商户私钥加签平台公钥验签；平台→商户（响应/回调）用平台私钥加签商户公钥验签。
 * 测试即网关：用对端密钥手工构造平台响应报文，再让 SDK 验证。
 */
final class WopClientTest extends VectorCase
{
    private const PATH = '/gateway/logistics.order.query';

    private WopClient $merchantClient;

    /** 平台视角客户端：构造响应报文（平台私钥加签 + 商户公钥包 DEK）。 */
    private WopClient $platformClient;

    protected function setUp(): void
    {
        $keys = self::keys();
        $this->merchantClient = new WopClient(new WopConfig(
            appKey: 'app_10012481831',
            securityReq: 'WOP-RSA3072-SHA256',
            privateKey: $keys['rsa3072']['privatePkcs8B64'],
            peerPublicKey: $keys['rsa3072']['publicSpkiB64'],
        ));
        $this->platformClient = new WopClient(new WopConfig(
            appKey: 'app_10012481831',
            securityReq: 'WOP-RSA3072-SHA256',
            privateKey: $keys['rsa3072']['privatePkcs8B64'],
            peerPublicKey: $keys['rsa3072']['publicSpkiB64'],
        ));
    }

    /** spec:F4/D2 — 有 body 必产 digest 且必入 signedHeaders（I1）。 */
    public function testBuildRequestL0WithBody(): void
    {
        $draft = $this->merchantClient->buildRequest('POST', self::PATH, '{"ok":true}', 'L0', 1774340000000, '0123456789abcdef0123456789abcdef');

        $this->assertSame('POST', $draft->method);
        $this->assertSame(self::PATH, $draft->path);
        $this->assertSame('{"ok":true}', $draft->wireBody, 'L0 wire body = 明文');
        $this->assertSame('app_10012481831', $draft->header('x-wop-appkey'));
        $this->assertSame('1774340000000', $draft->header('x-wop-timestamp'), 'F9 13 位毫秒时间戳');
        $this->assertSame('0123456789abcdef0123456789abcdef', $draft->header('x-wop-nonce'));
        $this->assertNull($draft->header('x-wop-encrypt'), 'L0 无加密指令头');

        $digest = $draft->header('x-wop-content-digest');
        $this->assertNotNull($digest);
        $this->assertSame('sha-256 ' . hash('sha256', '{"ok":true}'), $digest);

        // I1：digest 必入 signedHeaders
        $sign = \Wop\Sdk\SignHeader::parse($draft->header('x-wop-sign'));
        $this->assertContains('x-wop-content-digest', $sign->signedHeaders);
        foreach (['x-wop-appkey', 'x-wop-nonce', 'x-wop-timestamp'] as $required) {
            $this->assertContains($required, $sign->signedHeaders);
        }
        $this->assertSame('WOP-RSA3072-SHA256', $sign->securityReq);
        $this->assertSame(1800, $sign->expiredSeconds);

        // 自验签（等价网关侧：商户公钥验签重建的 canonical）
        $this->assertTrue($this->verifyDraftCanonical($draft));
    }

    /** spec:D2 — 无 body（GET）digest 头缺席。 */
    public function testBuildRequestGetWithoutBodyOmitsDigest(): void
    {
        $draft = $this->merchantClient->buildRequest('GET', self::PATH, null, 'L0', 1774340000000, 'nonce0000000000000000000000000');

        $this->assertSame('', $draft->wireBody);
        $this->assertNull($draft->header('x-wop-content-digest'), 'D2：无 body → digest 头缺席');
        $sign = \Wop\Sdk\SignHeader::parse($draft->header('x-wop-sign'));
        $this->assertNotContains('x-wop-content-digest', $sign->signedHeaders);
    }

    /** spec:F5 — L2：信封加密 + dek 头入签；密文可被对端（平台私钥）完整解开。 */
    public function testBuildRequestL2Envelope(): void
    {
        $body = '{"secret":"数据"}';
        $draft = $this->merchantClient->buildRequest('POST', self::PATH, $body, 'L2', 1774340000000, '0123456789abcdef0123456789abcdef');
        $this->assertNotSame($body, $draft->wireBody, 'L2 wire body 必为密文');
        // 线上信封契约：wire body = {"encrypted":"<base64url>"} JSON（网关 CryptoFilter 同构）
        $this->assertMatchesRegularExpression(
            '/^\\{"encrypted":"[A-Za-z0-9_-]+"\\}$/',
            $draft->wireBody,
            'L2 wire body 须为信封 JSON，密文为 base64url 无填充'
        );
        $encrypt = \Wop\Sdk\EncryptHeader::parse($draft->header('x-wop-encrypt'));
        $this->assertTrue($encrypt->isEncrypted());
        $this->assertNotNull($encrypt->dek);

        // digest 对象 = wire 字节（信封 JSON 载体，D2）
        $this->assertSame('sha-256 ' . hash('sha256', $draft->wireBody), $draft->header('x-wop-content-digest'));

        // I1：x-wop-encrypt 必入 signedHeaders
        $sign = \Wop\Sdk\SignHeader::parse($draft->header('x-wop-sign'));
        $this->assertContains('x-wop-encrypt', $sign->signedHeaders);
        $this->assertContains('x-wop-content-digest', $sign->signedHeaders);

        // 平台视角解开：信封提取 → DEK 解包（平台私钥即向量私钥，测试内同钥）→ alg 比对 → bulk 解密
        $dek = \Wop\Sdk\DekPayload::decode(\Wop\Sdk\RsaOaep::unwrap($encrypt->dek, self::keys()['rsa3072']['privatePkcs8B64']));
        $this->assertSame('AES-256-GCM', $dek->alg);
        $this->assertSame($body, \Wop\Sdk\Aes256Gcm::decrypt(
            \Wop\Sdk\Base64Url::decode(\Wop\Sdk\EncryptedEnvelope::extract($draft->wireBody)), $dek->iv, $dek->key
        ));

        $this->assertTrue($this->verifyDraftCanonical($draft), 'L2 签名同样覆盖密文载体摘要与加密头');
    }

    /** spec:§2 确定性 — 同输入同输出（固定 nonce/timestamp 注入下 L0 幂等）。 */
    public function testBuildRequestIsDeterministicForL0(): void
    {
        $a = $this->merchantClient->buildRequest('POST', self::PATH, 'same-body', 'L0', 1774340000000, '0123456789abcdef0123456789abcdef');
        $b = $this->merchantClient->buildRequest('POST', self::PATH, 'same-body', 'L0', 1774340000000, '0123456789abcdef0123456789abcdef');
        $this->assertSame($a->headers, $b->headers);
        $this->assertSame($a->wireBody, $b->wireBody);
    }

    /** spec:F9 — 默认（不注入）时 CSPRNG nonce/毫秒时间戳自行生成且互不相同。 */
    public function testF9DefaultsAreRandom(): void
    {
        $a = $this->merchantClient->buildRequest('GET', '/p');
        $b = $this->merchantClient->buildRequest('GET', '/p');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $a->header('x-wop-nonce'));
        $this->assertNotSame($a->header('x-wop-nonce'), $b->header('x-wop-nonce'), '每次请求 nonce 重新生成');
        $this->assertMatchesRegularExpression('/^\d{13}$/', $a->header('x-wop-timestamp'));
    }

    public function testBuildRequestRejectsUnknownLevel(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('L0/L2');
        $this->merchantClient->buildRequest('POST', '/p', 'x', 'L1');
    }

    public function testConfigRejectsSmSuite(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('SM2-SM3 套件暂未支持');
        new WopConfig('app', 'WOP-SM2-SM3', 'k', 'k');
    }

    // ==================== verifyResponse / F6 / I7 ====================

    /** F6 happy path：验签 → digest 复核 → DEK 解包 → alg 比对 → bulk 解密，全过 → ok + plaintext。 */
    public function testVerifyResponseL2HappyPath(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"code":"00000"}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        $this->assertTrue($result->ok);
        $this->assertSame('{"code":"00000"}', $result->plaintext);
        $this->assertNull($result->reason);
    }

    public function testVerifyResponseL0HappyPath(): void
    {
        [$headers, $wireBody] = $this->platformResponse('plain-body', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertTrue($result->ok);
        $this->assertSame('plain-body', $result->plaintext);
    }

    public function testVerifyResponseWithoutBodyStillVerifies(): void
    {
        $draft = $this->platformClient->buildRequest('GET', self::PATH, null, 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $result = $this->merchantClient->verifyResponse($draft->headers, $draft->wireBody, self::PATH, 'GET');
        $this->assertTrue($result->ok);
    }

    /** F6-1 先验签：签名被篡改时，即使 digest 也不匹配，对外只报签名失败。 */
    public function testVerifyResponseSignatureCheckedBeforeDigest(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        // 同时破坏 body（digest 将不匹配）与签名
        $headers['x-wop-sign'] = substr($headers['x-wop-sign'], 0, -2) . 'zz';
        $result = $this->merchantClient->verifyResponse($headers, $wireBody . 'x', self::PATH);

        $this->assertFalse($result->ok);
        $this->assertSame('签名验证失败', $result->reason, 'F6/I7：先验签，失败模糊不区分细节');
        $this->assertNull($result->plaintext);
    }

    /** F6-2 digest 复核在解密前：签名有效但密文被篡改 → 报摘要不匹配（明确），而非解密失败。 */
    public function testVerifyResponseDigestCheckedBeforeDecryption(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $tampered = $wireBody . 'x'; // 密文篡改 → digest 失败 + （若尝试解密）GCM 也会失败
        $result = $this->merchantClient->verifyResponse($headers, $tampered, self::PATH);

        $this->assertFalse($result->ok);
        $this->assertSame('摘要不匹配', $result->reason, 'F6：digest 复核（明确）先于解密（模糊）');
        $this->assertNull($result->plaintext);
    }

    /** F6-3 一致性比对（D8）在 bulk 解密前：dek alg 跨族 → 明确报不支持的报文算法。 */
    public function testVerifyResponseDekAlgFamilyCheckedBeforeBulkDecrypt(): void
    {
        // 用 SM4-GCM dek 载荷 + 无效 AES 密文体：若实现在 alg 比对前尝试解密，将得到"解密失败"而非一致性错误
        $headers = [];
        $wireBody = 'AAAA';
        $this->buildSignedResponse($headers, $wireBody, 'L2;dek=' . $this->wrappedSm4Dek(), 1774340000000, 'respnonce00000000000000000000a');
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        $this->assertFalse($result->ok);
        $this->assertSame('DEK 报文算法与套件不符', $result->reason, 'I3/D8：alg 族比对先于 bulk 解密，且语义明确');
    }

    /** I7 — DEK 解包失败与 GCM tag 失败对外同为"解密失败"，不区分细节。 */
    public function testVerifyResponseI7ObfuscatesDecryptFailures(): void
    {
        // 场景 A：DEK 篡改（OAEP 解包失败）
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $parsedEncrypt = \Wop\Sdk\EncryptHeader::parse($headers['x-wop-encrypt']);
        $badDek = substr($parsedEncrypt->dek, 0, 10) . ('A' === substr($parsedEncrypt->dek, 10, 1) ? 'B' : 'A') . substr($parsedEncrypt->dek, 11);
        $headers['x-wop-encrypt'] = 'L2;dek=' . $badDek;
        $this->reSignResponse($headers, $wireBody);
        $dekFailure = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        // 场景 B：GCM tag 失败（信封内密文尾部篡改，digest 已随 reSign 重算所以走到解密）
        [$headers2, $wireBody2] = $this->platformResponse('{"a":1}', 'L2', 1774340000001, 'respnonce00000000000000000000b');
        $cipher = \Wop\Sdk\EncryptedEnvelope::extract($wireBody2);
        $bytes = \Wop\Sdk\Base64Url::decode($cipher);
        $bytes[strlen($bytes) - 1] = $bytes[strlen($bytes) - 1] ^ "\x01";
        $tamperedWire = \Wop\Sdk\EncryptedEnvelope::wrap(\Wop\Sdk\Base64Url::encode($bytes));
        $this->reSignResponse($headers2, $tamperedWire);
        $tagFailure = $this->merchantClient->verifyResponse($headers2, $tamperedWire, self::PATH);

        $this->assertFalse($dekFailure->ok);
        $this->assertFalse($tagFailure->ok);
        $this->assertSame('解密失败', $dekFailure->reason);
        $this->assertSame('解密失败', $tagFailure->reason, 'I7：两种失败对外文案完全一致');
    }

    /** I7 — 验签失败原因模糊：篡改签名 / 换错公钥的 reason 一致。 */
    public function testVerifyResponseSignatureFailureIsUniform(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $headers['x-wop-sign'] = substr($headers['x-wop-sign'], 0, -4) . 'AAAA';
        $a = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        // 头缺失 → 解析类明确错误（帮助集成自查），不同于验签类
        $headers['x-wop-sign'] = 'not-a-sign-header';
        $b = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        $this->assertFalse($a->ok);
        $this->assertSame('签名验证失败', $a->reason);
        $this->assertFalse($b->ok);
        $this->assertStringContainsString('格式错误', (string) $b->reason, '解析类失败语义明确（10.2）');
    }

    /** verifyCallback — canonical URI 取回调 path。 */
    public function testVerifyCallbackUsesCallbackPath(): void
    {
        $callbackPath = '/merchant/callback/notify';
        [$headers, $wireBody] = $this->platformResponse('{"cb":1}', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        // 以回调 path 构签则回调验证通过
        $this->buildSignedResponse($headers, $wireBody, null, 1774340000000, 'respnonce00000000000000000000a', $callbackPath);
        $result = $this->merchantClient->verifyCallback($headers, $wireBody, 'https://merchant.example.com/merchant/callback/notify?id=1');
        $this->assertTrue($result->ok);
        $this->assertSame('{"cb":1}', $result->plaintext);

        // 换 path 验证必须失败（证明 path 参与了 canonical）
        $other = $this->merchantClient->verifyResponse($headers, $wireBody, '/other/path');
        $this->assertFalse($other->ok);
        $this->assertSame('签名验证失败', $other->reason);
    }

    public function testVerifyResponseRejectsSmSuite(): void
    {
        [$headers, $wireBody] = $this->platformResponse('x', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $headers['x-wop-sign'] = str_replace('WOP-RSA3072-SHA256', 'WOP-SM2-SM3', $headers['x-wop-sign']);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertFalse($result->ok);
        $this->assertStringContainsString('暂未支持', (string) $result->reason);
    }

    // ==================== helpers ====================

    /**
     * 构造平台→商户响应报文（平台私钥加签；L2 时平台用商户公钥包 DEK——测试中两者同钥，不影响断言语义）。
     *
     * @return array{0: array<string,string>, 1: string}
     */
    private function platformResponse(string $plainBody, string $level, int $timestampMs, string $nonce): array
    {
        $headers = [];
        $wireBody = $plainBody;
        $encryptHeader = null;
        if ($level === 'L2') {
            $dek = new \Wop\Sdk\DekPayload('AES-256-GCM', random_bytes(32), random_bytes(12));
            $result = \Wop\Sdk\Aes256Gcm::encrypt($plainBody, $dek->key, $dek->iv);
            // 真实网关线上契约：L2 wire body = {"encrypted":"<base64url>"} JSON 信封
            $wireBody = \Wop\Sdk\EncryptedEnvelope::wrap(\Wop\Sdk\Base64Url::encode($result->cipherTag));
            $encryptHeader = 'L2;dek=' . \Wop\Sdk\RsaOaep::wrap(
                $dek->encode(), self::keys()['rsa3072']['publicSpkiB64']
            );
        }
        $this->buildSignedResponse($headers, $wireBody, $encryptHeader, $timestampMs, $nonce);
        return [$headers, $wireBody];
    }

    /**
     * 按 signedHeaders 重建签名头（响应方向：nonce/timestamp/digest/encrypt）。
     *
     * @param array<string,string> $headers
     */
    private function buildSignedResponse(array &$headers, string $wireBody, ?string $encryptHeader, int $timestampMs, string $nonce, string $path = self::PATH): void
    {
        $headers['x-wop-nonce'] = $nonce;
        $headers['x-wop-timestamp'] = (string) $timestampMs;
        if ($wireBody !== '') {
            $headers['x-wop-content-digest'] = \Wop\Sdk\ContentDigest::build($wireBody, \Wop\Sdk\Suite::parse('WOP-RSA3072-SHA256'));
        }
        if ($encryptHeader !== null) {
            $headers['x-wop-encrypt'] = $encryptHeader;
        }

        $canonical = \Wop\Sdk\CanonicalRequest::build(
            'v1/1800',
            'POST',
            $path,
            '',
            \Wop\Sdk\CanonicalRequest::canonicalHeaders(array_intersect_key($headers, array_flip([
                'x-wop-nonce', 'x-wop-timestamp', 'x-wop-content-digest', 'x-wop-encrypt',
            ])))
        );
        $signature = \Wop\Sdk\RsaSigner::sign($canonical, self::keys()['rsa3072']['privatePkcs8B64']);
        $signedNames = implode(';', array_keys(array_intersect_key($headers, array_flip([
            'x-wop-nonce', 'x-wop-timestamp', 'x-wop-content-digest', 'x-wop-encrypt',
        ]))));
        $headers['x-wop-sign'] = "WOP-RSA3072-SHA256 v1/1800/{$signedNames}/{$signature}";
    }

    /** 重签（篡改后）：digest 头随 wire body 重算，保持签名有效以考察后续步骤。 */
    private function reSignResponse(array &$headers, string $wireBody): void
    {
        $sign = \Wop\Sdk\SignHeader::parse($headers['x-wop-sign']);
        // wire body 变化后 digest 头须同步重算（保持"签名有效"前提，只考察后续步骤）
        if (isset($headers['x-wop-content-digest'])) {
            $headers['x-wop-content-digest'] = \Wop\Sdk\ContentDigest::build($wireBody, \Wop\Sdk\Suite::parse('WOP-RSA3072-SHA256'));
        }
        $path = self::PATH;
        $canonical = \Wop\Sdk\CanonicalRequest::build('v1/1800', 'POST', $path, '', \Wop\Sdk\CanonicalRequest::canonicalHeaders(
            array_intersect_key($headers, array_flip($sign->signedHeaders))
        ));
        $signature = \Wop\Sdk\RsaSigner::sign($canonical, self::keys()['rsa3072']['privatePkcs8B64']);
        $headers['x-wop-sign'] = "WOP-RSA3072-SHA256 v1/1800/" . implode(';', $sign->signedHeaders) . "/{$signature}";
    }


    /** 用对端公钥验签 draft 的 canonical（模拟网关侧验签）。 */
    private function verifyDraftCanonical(\Wop\Sdk\RequestDraft $draft): bool
    {
        $sign = \Wop\Sdk\SignHeader::parse($draft->header('x-wop-sign'));
        $canonical = \Wop\Sdk\CanonicalRequest::build(
            'v1/1800',
            $draft->method,
            $draft->path,
            '',
            \Wop\Sdk\CanonicalRequest::canonicalHeaders(
                array_intersect_key($draft->headers, array_flip($sign->signedHeaders))
            )
        );
        return \Wop\Sdk\RsaSigner::verify($canonical, $sign->signature, self::keys()['rsa3072']['publicSpkiB64']);
    }

    /** 构造"已用规格参数包装的 SM4-GCM DEK"（跨族负向量载体）。 */
    private function wrappedSm4Dek(): string
    {
        $sm4 = self::vector('dekPayload', 'dek-sm2');
        return \Wop\Sdk\RsaOaep::wrap(
            $sm4['expected'], self::keys()['rsa3072']['publicSpkiB64']
        );
    }


    /** F6-2b：digest 头整体缺失但有 body → 摘要不匹配（明确）。 */
    public function testVerifyResponseMissingDigestHeaderRejected(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        unset($headers['x-wop-content-digest']);
        $this->reSignResponse($headers, $wireBody);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertFalse($result->ok);
        $this->assertSame('摘要不匹配', $result->reason);
    }

    /** L2 密文但 encrypt 头缺失：验签+digest 过后按 L0 原文返回（协议层无解密指令）。 */
    public function testVerifyResponseCipherBodyWithoutEncryptHeaderTreatedAsL0(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        unset($headers['x-wop-encrypt']);
        $this->reSignResponse($headers, $wireBody);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertTrue($result->ok);
        $this->assertSame($wireBody, $result->plaintext);
    }

    /** GET + L2（body null）：不产信封、不产 digest，等同 L0 空体。 */
    public function testBuildRequestGetL2WithoutBodyDegradesToPlain(): void
    {
        $draft = $this->merchantClient->buildRequest('GET', self::PATH, null, 'L2', 1774340000000, 'nonce0000000000000000000000000');
        $this->assertNull($draft->header('x-wop-encrypt'));
        $this->assertNull($draft->header('x-wop-content-digest'));
    }

    /** 回调 URL 无 path → canonical path 取 "/"。 */
    public function testVerifyCallbackUrlWithoutPathUsesRoot(): void
    {
        [$headers, $wireBody] = $this->platformResponse('x', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $this->buildSignedResponse($headers, $wireBody, null, 1774340000000, 'respnonce00000000000000000000a', '/');
        $result = $this->merchantClient->verifyCallback($headers, $wireBody, 'https://merchant.example.com');
        $this->assertTrue($result->ok);
    }

    /** WopConfig 可选 gatewayBaseUrl 字段。 */
    public function testConfigOptionalBaseUrl(): void
    {
        $config = new WopConfig('app', 'WOP-RSA4096-SHA256', self::keys()['rsa4096']['privatePkcs8B64'], self::keys()['rsa4096']['publicSpkiB64'], 'https://gw.example.com');
        $this->assertSame('https://gw.example.com', $config->gatewayBaseUrl);
        $this->assertSame(4096, $config->suite->keyLength);
    }


    /** I7：L2 头无 dek 段（解包输入缺失）→ 解密失败（模糊）。 */
    public function testVerifyResponseL2WithoutDekFailsObfuscated(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        // 替换为无 dek 的 L2 指令并重签（wire/digest 不变）
        $headers['x-wop-encrypt'] = 'L2';
        $this->reSignResponse($headers, $wireBody);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertFalse($result->ok);
        $this->assertSame('解密失败', $result->reason);
    }

    /** I7：DEK 解包成功但载荷非 alg$key$iv → 解密失败（模糊）。 */
    public function testVerifyResponseGarbageDekPayloadFailsObfuscated(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $headers['x-wop-encrypt'] = 'L2;dek=' . \Wop\Sdk\RsaOaep::wrap('garbage-not-a-dek', self::keys()['rsa3072']['publicSpkiB64']);
        $this->reSignResponse($headers, $wireBody);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);
        $this->assertFalse($result->ok);
        $this->assertSame('解密失败', $result->reason);
    }

    // ==================== L2 线上信封契约 ====================

    /** L2 指令 + 裸密文（非信封 JSON）→ 协议类明确失败，而非解密类模糊。 */
    public function testVerifyResponseL2RejectsNonEnvelopeBody(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        // 旧线上形态：裸 base64url 密文直作 wire body（信封契约修复前的自产自验形态）
        $rawCipher = \Wop\Sdk\EncryptedEnvelope::extract($wireBody);
        $this->reSignResponse($headers, $rawCipher);
        $result = $this->merchantClient->verifyResponse($headers, $rawCipher, self::PATH);

        $this->assertFalse($result->ok);
        $this->assertStringContainsString('信封', (string) $result->reason, '非信封 wire body 须按协议类明确报错');
    }

    /** 信封缺 encrypted 字段 → 协议类明确失败。 */
    public function testVerifyResponseL2RejectsEnvelopeWithoutEncryptedField(): void
    {
        [$headers] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $missing = '{"other":"x"}';
        $this->reSignResponse($headers, $missing);
        $result = $this->merchantClient->verifyResponse($headers, $missing, self::PATH);

        $this->assertFalse($result->ok);
        $this->assertStringContainsString('缺少 encrypted', (string) $result->reason);
    }

    /** 信封 encrypted 非字符串 / 非 JSON / 非 JSON 对象 → 协议类明确失败。 */
    public function testVerifyResponseL2RejectsMalformedEnvelopes(): void
    {
        foreach ([
            'not-json-at-all' => '非 JSON',
            '12345' => 'JSON 标量',
            '["encrypted","x"]' => 'JSON 数组',
            '{}' => '空对象',
            '{"encrypted":123}' => '非字符串值',
            '{"encrypted":""}' => '空串',
        ] as $bad => $note) {
            [$headers] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
            $this->reSignResponse($headers, (string) $bad); // 数字串键会被 PHP 转 int，此处还原为 wire 字符串
            $result = $this->merchantClient->verifyResponse($headers, (string) $bad, self::PATH);
            $this->assertFalse($result->ok, "应拒绝（{$note}）");
            $this->assertStringContainsString('信封', (string) $result->reason, "协议类明确报错（{$note}）");
        }
    }

    /** 信封容忍未知字段（前向兼容）：附加字段不影响提取与解密。 */
    public function testVerifyResponseL2EnvelopeToleratesUnknownFields(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L2', 1774340000000, 'respnonce00000000000000000000a');
        $cipher = \Wop\Sdk\EncryptedEnvelope::extract($wireBody);
        $extended = json_encode(['encrypted' => $cipher, 'ext' => ['ts' => 1], 'v' => 'future'], JSON_UNESCAPED_SLASHES);
        $this->reSignResponse($headers, (string) $extended);
        $result = $this->merchantClient->verifyResponse($headers, (string) $extended, self::PATH);

        $this->assertTrue($result->ok);
        $this->assertSame('{"a":1}', $result->plaintext);
    }

    /** encrypt 头 level 非法 → 结构化 fail（解析类明确），不再逃逸为未捕获异常。 */
    public function testVerifyResponseInvalidEncryptHeaderFailsStructured(): void
    {
        [$headers, $wireBody] = $this->platformResponse('{"a":1}', 'L0', 1774340000000, 'respnonce00000000000000000000a');
        $headers['x-wop-encrypt'] = 'L1';
        $this->reSignResponse($headers, $wireBody);
        $result = $this->merchantClient->verifyResponse($headers, $wireBody, self::PATH);

        $this->assertFalse($result->ok);
        $this->assertStringContainsString('L0/L2', (string) $result->reason, '解析类失败语义明确（10.2）');
    }
}
