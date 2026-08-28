<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\Base64Url;
use Wop\Sdk\WopException;

/** spec:F7 — 线上二进制编码 base64url 无填充，严格模式（拒 `=`、`+`、`/`）。 */
final class Base64UrlTest extends VectorCase
{
    public function testEncodeIsUnpaddedUrlSafe(): void
    {
        // 2 字节 → 3 字符；11 字节 → 15 字符（均无填充）
        $this->assertSame('AAEC', Base64Url::encode("\x00\x01\x02"));
        $this->assertSame('', Base64Url::encode(''));
        $raw = random_bytes(11);
        $encoded = Base64Url::encode($raw);
        $this->assertSame(15, strlen($encoded));
        $this->assertDoesNotMatchRegularExpression('/[=+\/]/', $encoded);
        $this->assertSame($raw, Base64Url::decode($encoded));
    }

    public function testDecodeRejectsPadding(): void
    {
        // spec:formatRules b64url-with-padding — "abc=" 必须拒绝
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('base64url');
        Base64Url::decode('abc=');
    }

    public function testDecodeRejectsIllegalChar(): void
    {
        // spec:formatRules b64url-illegal-char — "ab+c" 必须拒绝（标准字母表 + 不在 url 字母表）
        $this->expectException(WopException::class);
        Base64Url::decode('ab+c');
    }

    public function testDecodeRejectsSlash(): void
    {
        $this->expectException(WopException::class);
        Base64Url::decode('ab/c');
    }

    public function testDecodeRejectsInvalidLength(): void
    {
        $this->expectException(WopException::class);
        Base64Url::decode('abcde'); // mod 4 == 1，不可能合法
    }

    public function testDecodeVectorSignatureRoundtrip(): void
    {
        // 向量签名恒 512 字符（RSA3072）且解回 384 字节
        $vec = self::vector('signature', 'rsa3072-sign');
        $sig = Base64Url::decode($vec['expectedSigB64u']);
        $this->assertSame(384, strlen($sig));
        $this->assertSame($vec['expectedSigB64u'], Base64Url::encode($sig));
    }


    public function testDecodeAcceptsUnpaddedTailLengths(): void
    {
        // 2/3 字符尾部为合法无填充形态（线上编码本身无填充）
        $this->assertSame('i', Base64Url::decode('ab'));
        $this->assertSame(2, strlen(Base64Url::decode('abc')));
        $this->assertSame('aQ', Base64Url::encode('i'));
    }
}
