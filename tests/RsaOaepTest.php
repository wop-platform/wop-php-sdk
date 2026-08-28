<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\RsaOaep;

/**
 * spec:F5/F2(D10) — RSA-OAEP 显式双 SHA-256 + 空 label（phpseclib withMGFHash）。
 * 向量：oaep3072/4096-unwrap 字节级、oaep3072-mgf1sha1-trap 必须拒。
 */
final class RsaOaepTest extends VectorCase
{
    public function testUnwrap3072MatchesVector(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep3072-unwrap');
        $plain = RsaOaep::unwrap($vec['cipherB64u'], self::keys()['rsa3072']['privatePkcs8B64']);
        $this->assertSame($vec['expectedPlaintext'], $plain);
    }

    public function testUnwrap4096MatchesVector(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep4096-unwrap');
        $plain = RsaOaep::unwrap($vec['cipherB64u'], self::keys()['rsa4096']['privatePkcs8B64']);
        $this->assertSame($vec['expectedPlaintext'], $plain);
    }

    /** F2 钉子：以错误 MGF1（SHA-1）包装的密文，用规格参数（双 SHA-256）解包必须失败。 */
    public function testMgf1Sha1TrapIsRejected(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep3072-mgf1sha1-trap');
        $this->assertNull(RsaOaep::unwrap($vec['cipherB64u'], self::keys()['rsa3072']['privatePkcs8B64']));
    }

    public function testUnwrapRejectsTamperedCipher(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep3072-unwrap');
        $tampered = substr($vec['cipherB64u'], 0, 20) . ('A' === substr($vec['cipherB64u'], 20, 1) ? 'B' : 'A') . substr($vec['cipherB64u'], 21);
        $this->assertNull(RsaOaep::unwrap($tampered, self::keys()['rsa3072']['privatePkcs8B64']));
    }

    /** roundtrip：OAEP 加密随机化无法字节钉；产出密文经规格参数解包须等于明文。 */
    public function testWrapRoundtrip(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep3072-wrap-roundtrip');
        $keys = self::keys()['rsa3072'];
        $wrapped = RsaOaep::wrap($vec['plaintext'], $keys['publicSpkiB64']);
        $this->assertNotSame($vec['plaintext'], $wrapped);
        $this->assertSame($vec['plaintext'], RsaOaep::unwrap($wrapped, $keys['privatePkcs8B64']));
    }

    public function testWrap4096Roundtrip(): void
    {
        $vec = self::vector('keyEncrypt', 'oaep3072-wrap-roundtrip');
        $keys = self::keys()['rsa4096'];
        $wrapped = RsaOaep::wrap($vec['plaintext'], $keys['publicSpkiB64']);
        $this->assertSame($vec['plaintext'], RsaOaep::unwrap($wrapped, $keys['privatePkcs8B64']));
    }
}
