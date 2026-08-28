<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wop\Sdk\DekPayload;
use Wop\Sdk\WopException;

/** spec:F5/§6 — DEK 载荷 `alg$base64url(key)$base64url(iv)`。 */
final class DekPayloadTest extends VectorCase
{
    public function testEncodeRsaVector(): void
    {
        $vec = self::vector('dekPayload', 'dek-rsa');
        $payload = new DekPayload($vec['alg'], self::b64uDecode($vec['keyB64u']), self::b64uDecode($vec['ivB64u']));
        $this->assertSame($vec['expected'], $payload->encode());
    }

    public function testDecodeRsaVector(): void
    {
        $vec = self::vector('dekPayload', 'dek-rsa');
        $payload = DekPayload::decode($vec['expected']);
        $this->assertSame($vec['alg'], $payload->alg);
        $this->assertSame(self::b64uDecode($vec['keyB64u']), $payload->key);
        $this->assertSame(self::b64uDecode($vec['ivB64u']), $payload->iv);
    }

    public function testDecodeRejectsWrongAlg(): void
    {
        // 一致性类：RSA 套件下 alg 段必须为 AES-256-GCM（§6.2），SM4-GCM 属跨族
        $vec = self::vector('dekPayload', 'dek-sm2');
        $payload = DekPayload::decode($vec['expected']);
        $this->assertFalse($payload->algMatches('WOP-RSA3072-SHA256'));
        $this->assertTrue($payload->algMatches('WOP-SM2-SM3'));
        $rsa = DekPayload::decode(self::vector('dekPayload', 'dek-rsa')['expected']);
        $this->assertTrue($rsa->algMatches('WOP-RSA3072-SHA256'));
        $this->assertFalse($rsa->algMatches('WOP-SM2-SM3'));
    }

    /** spec:A2 解析负向量：段数/空段/非法 base64url。 */
    #[DataProvider('malformedProvider')]
    public function testDecodeRejectsMalformed(string $text): void
    {
        $this->expectException(WopException::class);
        DekPayload::decode($text);
    }

    /** @return list<list<string>> */
    public static function malformedProvider(): array
    {
        return [
            [''],
            ['AES-256-GCM'],
            ['AES-256-GCM$key'],
            ['AES-256-GCM$key$iv$extra'],
            ['$key$iv'],
            ['AES-256-GCM$$iv'],
            ['AES-256-GCM$key-'],
            ['AES-256-GCM$key$iv='],
        ];
    }
}
