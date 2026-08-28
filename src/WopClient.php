<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * WOP 商户客户端：协议核心入口。
 *
 * 出向：buildRequest（L0 明文 / L2 数字信封）→ RequestDraft
 * 入向：verifyResponse / verifyCallback — F6 顺序固定：
 *   验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密；
 *   验签/解密失败对外模糊（I7），解析/格式/一致性类失败语义明确（10.2）。
 */
final class WopClient
{
    public const DEFAULT_EXPIRED_SECONDS = 1800;
    private const HEADER_APPKEY = 'x-wop-appkey';
    private const HEADER_TIMESTAMP = 'x-wop-timestamp';
    private const HEADER_NONCE = 'x-wop-nonce';
    private const HEADER_SIGN = 'x-wop-sign';
    private const HEADER_ENCRYPT = 'x-wop-encrypt';
    private const HEADER_CONTENT_DIGEST = 'x-wop-content-digest';

    private const REASON_SIGN_FAIL = '签名验证失败';
    private const REASON_DIGEST_MISMATCH = '摘要不匹配';
    private const REASON_DECRYPT_FAIL = '解密失败';
    private const REASON_DEK_ALG_MISMATCH = 'DEK 报文算法与套件不符';

    public function __construct(private readonly WopConfig $config)
    {
    }

    /**
     * 构造已签名请求（可重放生成：同输入同输出，F9 随机量可注入）。
     *
     * @param string|null $body        业务明文（GET 传 null → digest 头缺席，D2）
     * @param string      $level       L0 | L2
     * @param int|null    $timestampMs 13 位毫秒时间戳（缺省当前时间，F9）
     * @param string|null $nonce       32 位随机串（缺省 CSPRNG 生成，F9）
     */
    public function buildRequest(
        string $method,
        string $path,
        ?string $body = null,
        string $level = EncryptHeader::LEVEL_L0,
        ?int $timestampMs = null,
        ?string $nonce = null
    ): RequestDraft {
        EncryptHeader::validateLevel($level);
        $isL2 = \strcasecmp($level, EncryptHeader::LEVEL_L2) === 0;

        $headers = [
            self::HEADER_APPKEY => $this->config->appKey,
            self::HEADER_TIMESTAMP => (string) ($timestampMs ?? $this->currentMillis()),
            self::HEADER_NONCE => $nonce ?? $this->newNonce(),
        ];

        // L2：信封加密（CSPRNG DEK + IV），wire body = base64url(ciphertext||tag)
        if ($isL2 && $body !== null) {
            $dek = new DekPayload($this->config->suite->dekAlg, \random_bytes(Aes256Gcm::KEY_BYTES), \random_bytes(Aes256Gcm::IV_BYTES));
            $result = Aes256Gcm::encrypt($body, $dek->key, $dek->iv);
            $wireBody = Base64Url::encode($result->cipherTag);
            $headers[self::HEADER_ENCRYPT] = EncryptHeader::build(
                EncryptHeader::LEVEL_L2,
                RsaOaep::wrap($dek->encode(), $this->config->peerPublicKey)
            );
        } else {
            $wireBody = $body ?? '';
        }

        // D2：有 wire body 必产 digest 且必入 signedHeaders（I1）；无 body 缺席
        if ($wireBody !== '') {
            $headers[self::HEADER_CONTENT_DIGEST] = ContentDigest::build($wireBody, $this->config->suite);
        }

        $canonical = CanonicalRequest::build(
            'v1/' . self::DEFAULT_EXPIRED_SECONDS,
            $method,
            $path,
            '',
            CanonicalRequest::canonicalHeaders($headers)
        );
        $signature = RsaSigner::sign($canonical, $this->config->privateKey);
        $headers[self::HEADER_SIGN] = SignHeader::build(
            $this->config->suite->securityReq,
            self::DEFAULT_EXPIRED_SECONDS,
            \array_keys($headers),
            $signature
        );
        return new RequestDraft(\strtoupper($method), $path, $headers, $wireBody);
    }

    /**
     * 验证平台同步响应（canonical URI 取网关 API 路径）。
     *
     * @param array<string, string> $headers
     */
    public function verifyResponse(array $headers, string $body, string $gatewayPath, string $method = 'POST'): VerifyResult
    {
        return $this->verify($headers, $body, $gatewayPath, $method);
    }

    /**
     * 验证平台异步回调（canonical URI 取回调 URL 的 path，不含 query）。
     *
     * @param array<string, string> $headers
     */
    public function verifyCallback(array $headers, string $body, string $callbackUrl): VerifyResult
    {
        $path = (string) \parse_url($callbackUrl, PHP_URL_PATH);
        return $this->verify($headers, $body, $path === '' ? '/' : $path, 'POST');
    }

    /**
     * F6：验签 → digest 复核 → DEK 解包 → alg 族比对（解包后、bulk 解密前）→ bulk 解密。
     *
     * @param array<string, string> $headers
     */
    private function verify(array $headers, string $body, string $canonicalPath, string $method): VerifyResult
    {
        // 头解析与套件装配（解析类/支持类失败语义明确）
        try {
            $signHeader = $this->header($headers, self::HEADER_SIGN) ?? '';
            $parsed = SignHeader::parse($signHeader);
            $suite = Suite::parse($parsed->securityReq);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }

        // ① 验签（先验签后解密，I2；失败模糊，I7）
        $canonical = CanonicalRequest::build(
            $parsed->protocolVersion . '/' . $parsed->expiredSeconds,
            $method,
            $canonicalPath,
            '',
            CanonicalRequest::canonicalHeaders($this->collectSigned($headers, $parsed->signedHeaders))
        );
        if (!RsaSigner::verify($canonical, $parsed->signature, $this->config->peerPublicKey)) {
            return VerifyResult::fail(self::REASON_SIGN_FAIL);
        }

        // ② digest 复核（明确；摘要对象 = wire 字节）
        $digestHeader = $this->header($headers, self::HEADER_CONTENT_DIGEST);
        if ($body !== '') {
            if ($digestHeader === null || !ContentDigest::matches($digestHeader, $body)) {
                return VerifyResult::fail(self::REASON_DIGEST_MISMATCH);
            }
        }

        $encryptHeader = EncryptHeader::parse($this->header($headers, self::HEADER_ENCRYPT));
        if (!$encryptHeader->isEncrypted() || $body === '') {
            return VerifyResult::ok($body);
        }

        // ③ DEK 解包（失败模糊，I7）
        $dekPlain = $encryptHeader->dek === null ? null : RsaOaep::unwrap($encryptHeader->dek, $this->config->privateKey);
        if ($dekPlain === null) {
            return VerifyResult::fail(self::REASON_DECRYPT_FAIL);
        }
        try {
            $dek = DekPayload::decode($dekPlain);
        } catch (WopException) {
            return VerifyResult::fail(self::REASON_DECRYPT_FAIL);
        }

        // ④ alg 族比对（bulk 解密前，D8/I3；明确）
        if (!$dek->algMatches($suite->securityReq)) {
            return VerifyResult::fail(self::REASON_DEK_ALG_MISMATCH);
        }

        // ⑤ bulk 解密（失败模糊，I7）
        $plaintext = Aes256Gcm::decrypt(Base64Url::decode($body), $dek->iv, $dek->key);
        return $plaintext === null
            ? VerifyResult::fail(self::REASON_DECRYPT_FAIL)
            : VerifyResult::ok($plaintext);
    }

    /** @param array<string, string> $headers */
    private function header(array $headers, string $name): ?string
    {
        foreach ($headers as $key => $value) {
            if (\strcasecmp($key, $name) === 0) {
                return $value;
            }
        }
        return null;
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private function collectSigned(array $headers, array $signedNames): array
    {
        $collected = [];
        foreach ($signedNames as $name) {
            $value = $this->header($headers, $name);
            if ($value !== null) {
                $collected[$name] = $value;
            }
        }
        return $collected;
    }

    /** F9：13 位毫秒 Unix 时间戳。 */
    private function currentMillis(): int
    {
        return (int) (\microtime(true) * 1000);
    }

    /** F9：CSPRNG 32 位随机串。 */
    private function newNonce(): string
    {
        return \bin2hex(\random_bytes(16));
    }
}
