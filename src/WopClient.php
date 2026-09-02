<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * WOP 商户客户端：协议核心入口。
 *
 * 出向：buildRequest（L0 明文 / L2 数字信封）→ RequestDraft
 * 入向：verifyResponse / verifyCallback — F6 顺序固定：
 *   结构前置校验 → 验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密；
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

    /** 稳定对外文案（interop canonical class 映射锚点，I7 模糊类）。 */
    public const REASON_SIGN_FAIL = '签名验证失败';
    public const REASON_DIGEST_MISMATCH = '摘要不匹配';
    public const REASON_DECRYPT_FAIL = '解密失败';
    public const REASON_DEK_ALG_MISMATCH = 'DEK 报文算法与套件不符';

    private const OAEP_SEED_BYTES = 32;

    /** 以不可变配置装配客户端（securityReq 已在 WopConfig 构造期固化为 Suite）。 */
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
     * @param \Closure(int): string|null $random 确定性随机源（联调用；生产禁用——IV 复用即 I4 违规）。
     *        消费顺序合同（wop-specs/interop/v1）：[16B nonce 池（nonce 已注入时跳过）]
     *        [32B CEK][12B IV][32B OAEP seed]——跨仓 build 字节级复现依赖此序
     */
    public function buildRequest(
        string $method,
        string $path,
        ?string $body = null,
        string $level = EncryptHeader::LEVEL_L0,
        ?int $timestampMs = null,
        ?string $nonce = null,
        ?\Closure $random = null,
    ): RequestDraft {
        EncryptHeader::validateLevel($level);
        $isL2 = \strcasecmp($level, EncryptHeader::LEVEL_L2) === 0;
        $random ??= static fn (int $length): string => \random_bytes($length);

        $headers = [
            self::HEADER_APPKEY => $this->config->appKey,
            self::HEADER_TIMESTAMP => (string) ($timestampMs ?? $this->currentMillis()),
            self::HEADER_NONCE => $nonce ?? \bin2hex($random(16)),
        ];

        // L2：信封加密（CSPRNG DEK + IV），wire body = {"encrypted":"<base64url(ciphertext||tag)>"}
        // （线上信封契约与网关 CryptoFilter 一致，L2 线上体恒为 JSON）
        if ($isL2 && $body !== null) {
            $dek = new DekPayload(
                $this->config->suite->dekAlg,
                $random(Aes256Gcm::KEY_BYTES),
                $random(Aes256Gcm::IV_BYTES),
            );
            $result = Aes256Gcm::encrypt($body, $dek->key, $dek->iv);
            $wireBody = EncryptedEnvelope::wrap(Base64Url::encode($result->cipherTag));
            $headers[self::HEADER_ENCRYPT] = EncryptHeader::build(
                EncryptHeader::LEVEL_L2,
                RsaOaep::wrap($dek->encode(), $this->config->peerPublicKey, $random(self::OAEP_SEED_BYTES))
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
        $signedNames = \array_keys($headers);
        \sort($signedNames, SORT_STRING); // signedHeaders 段按名称排序（跨仓字节级一致）
        $headers[self::HEADER_SIGN] = SignHeader::build(
            $this->config->suite->securityReq,
            self::DEFAULT_EXPIRED_SECONDS,
            $signedNames,
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
     * F6：结构前置校验 → 验签 → digest 复核 → DEK 解包 → alg 族比对（解包后、bulk 解密前）
     * → 信封提取 → bulk 解密。
     *
     * @param array<string, string> $headers
     */
    private function verify(array $headers, string $body, string $canonicalPath, string $method): VerifyResult
    {
        // 0. 头解析与套件装配（解析类/支持类失败语义明确）
        try {
            $signHeader = $this->header($headers, self::HEADER_SIGN) ?? '';
            $parsed = SignHeader::parse($signHeader);
            $suite = Suite::parse($parsed->securityReq);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
        // 响应套件与客户端装配套件一致性（公开结构知识，明确）
        if ($suite->securityReq !== $this->config->suite->securityReq) {
            return VerifyResult::fail(
                '响应套件 ' . $suite->securityReq . ' 与客户端配置 ' . $this->config->suite->securityReq . ' 不符'
            );
        }

        // 1. 结构前置校验（公开协议知识，明确拒绝；均不依赖密钥，先于验签）：
        //    D2 有 body 必传 digest、I1 digest 必入 signedHeaders、D2 反向无 body 不携带
        $hasBody = $body !== '';
        $digestHeader = $this->header($headers, self::HEADER_CONTENT_DIGEST);
        if ($hasBody) {
            if ($digestHeader === null) {
                return VerifyResult::fail(self::REASON_DIGEST_MISMATCH);
            }
            if (!\in_array(self::HEADER_CONTENT_DIGEST, $parsed->signedHeaders, true)) {
                return VerifyResult::fail('x-wop-content-digest 未列入 signedHeaders（I1）');
            }
        } elseif ($digestHeader !== null) {
            return VerifyResult::fail('无响应体不应携带 x-wop-content-digest');
        }

        // 2. 验签（I2：先验签后解密）：按 signedHeaders 从真实响应头重建 canonical；
        //    已签名头缺席为协议类明确错误，签名段 b64url/定长为公开结构知识（明确），
        //    密码学验签失败模糊（I7）
        try {
            $signed = $this->collectSigned($headers, $parsed->signedHeaders);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
        try {
            $signature = Base64Url::decode($parsed->signature);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
        if (\strlen($signature) !== \intdiv($suite->keyLength, 8)) {
            return VerifyResult::fail(
                '签名长度 ' . \strlen($signature) . ' 字节与套件 ' . $suite->securityReq . ' 定长不符'
            );
        }
        $canonical = CanonicalRequest::build(
            $parsed->protocolVersion . '/' . $parsed->expiredSeconds,
            $method,
            $canonicalPath,
            '',
            CanonicalRequest::canonicalHeaders($signed)
        );
        if (!RsaSigner::verify($canonical, $parsed->signature, $this->config->peerPublicKey)) {
            return VerifyResult::fail(self::REASON_SIGN_FAIL);
        }

        // 3. digest 复核（明确；摘要对象 = wire 字节）：格式/族耦合非法 → 协议类；
        //    值不匹配 → 完整性类（n02/n03 分类分界）
        if ($hasBody) {
            try {
                ContentDigest::validate($digestHeader, $suite);
            } catch (WopException $e) {
                return VerifyResult::fail($e->getMessage());
            }
            if (!ContentDigest::matches($digestHeader, $body)) {
                return VerifyResult::fail(self::REASON_DIGEST_MISMATCH);
            }
        }

        try {
            $encryptHeader = EncryptHeader::parse($this->header($headers, self::HEADER_ENCRYPT));
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
        if (!$encryptHeader->isEncrypted() || $body === '') {
            return VerifyResult::ok($body);
        }

        // 4. DEK 解包：裸 L2 缺 dek 段与密文段 b64url 结构非法均为公开头结构知识
        //    → 协议类明确（interop 裁决 0 号，n17）；解包失败与载荷结构畸形为解密类模糊（I7，除 alg 跨族 D8 外）
        if ($encryptHeader->dek === null) {
            return VerifyResult::fail('x-wop-encrypt 为 L2 但缺少 dek 段');
        }
        try {
            Base64Url::decode($encryptHeader->dek);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
        $dekPlain = RsaOaep::unwrap($encryptHeader->dek, $this->config->privateKey);
        if ($dekPlain === null) {
            return VerifyResult::fail(self::REASON_DECRYPT_FAIL);
        }
        try {
            $dek = DekPayload::decode($dekPlain);
        } catch (WopException) {
            return VerifyResult::fail(self::REASON_DECRYPT_FAIL);
        }

        // 5. alg 族比对（bulk 解密前，D8/I3；明确）
        if (!$dek->algMatches($suite->securityReq)) {
            return VerifyResult::fail(self::REASON_DEK_ALG_MISMATCH);
        }

        // 6. 信封提取 + bulk 解密（提取/编码为协议类明确错误；GCM 解密失败模糊，I7）
        try {
            $cipherB64Url = EncryptedEnvelope::extract($body);
            $plaintext = Aes256Gcm::decrypt(Base64Url::decode($cipherB64Url), $dek->iv, $dek->key);
        } catch (WopException $e) {
            return VerifyResult::fail($e->getMessage());
        }
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
     * 按 signedHeaders 收集真实响应头；已签名头缺席抛 WopException（协议类明确）。
     *
     * @param array<string, string> $headers
     * @param list<string> $signedNames
     * @return array<string, string>
     */
    private function collectSigned(array $headers, array $signedNames): array
    {
        $collected = [];
        foreach ($signedNames as $name) {
            $value = $this->header($headers, $name);
            if ($value === null) {
                throw new WopException('已签名头 ' . $name . ' 在响应中缺失');
            }
            $collected[$name] = $value;
        }
        return $collected;
    }

    /** F9：13 位毫秒 Unix 时间戳。 */
    private function currentMillis(): int
    {
        return (int) (\microtime(true) * 1000);
    }
}
