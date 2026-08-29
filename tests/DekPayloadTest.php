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

    /** spec:A2 支持类负向量：alg 段不在 D13 注册表（AES-256-GCM/SM4-GCM 之外）。 */
    public function testDecodeRejectsUnknownAlg(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('不在支持列表');
        DekPayload::decode('CHACHA20-POLY1305$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x01", 32)) . '$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x02", 12)));
    }

    /** spec:A2 结构负向量：iv 段解码后非 12 字节。 */
    public function testDecodeRejectsWrongIvLength(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('iv 须 12 字节');
        DekPayload::decode('AES-256-GCM$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x01", 32)) . '$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x02", 11)));
    }

    /** 解析负向量文案钉死（段数/空段/密钥长度，商户排错界面价值）。 */
    public function testDecodeRejectMessageTexts(): void
    {
        $b32 = \Wop\Sdk\Base64Url::encode(str_repeat("\x01", 32));
        foreach ([
            'AES-256-GCM$key' => '应为 alg$key$iv',
            'AES-256-GCM$$iv' => '存在空段',
            '$key$iv' => '存在空段',
            'AES-256-GCM$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x01", 31)) . '$' . \Wop\Sdk\Base64Url::encode(str_repeat("\x02", 12)) => '载荷 alg AES-256-GCM 密钥须 32 字节，实际 31',
        ] as $payload => $fragment) {
            try {
                DekPayload::decode($payload);
                $this->fail("应拒绝: {$payload}");
            } catch (WopException $e) {
                $this->assertStringContainsString($fragment, $e->getMessage(), $payload);
            }
        }
    }
}
