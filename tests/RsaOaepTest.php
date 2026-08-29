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

    /** interop 随机流合同：显式 seed 下 wrap 确定性（同 seed 同密文），且可被规格参数解包。 */
    public function testWrapWithExplicitSeedIsDeterministic(): void
    {
        $keys = self::keys()['rsa3072'];
        $seed = \random_bytes(32);
        $a = RsaOaep::wrap('deterministic-payload', $keys['publicSpkiB64'], $seed);
        $b = RsaOaep::wrap('deterministic-payload', $keys['publicSpkiB64'], $seed);
        $this->assertSame($a, $b, '同 seed 必产同密文（OAEP-from-stream）');
        $this->assertNotSame($a, RsaOaep::wrap('deterministic-payload', $keys['publicSpkiB64'], \strrev($seed)));
        $this->assertSame('deterministic-payload', RsaOaep::unwrap($a, $keys['privatePkcs8B64']));
    }

    /** seed 长度非 32 字节 → 明确拒绝（结构知识，不进密码学区）。 */
    public function testWrapRejectsShortSeed(): void
    {
        $this->expectExceptionMessage('OAEP seed 须为 32 字节');
        RsaOaep::wrap('x', self::keys()['rsa3072']['publicSpkiB64'], 'short');
    }

    /** 明文超出 OAEP 容量（k - 2·hLen - 2）→ 明确拒绝。 */
    public function testWrapRejectsOversizedPlaintext(): void
    {
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('明文超长');
        RsaOaep::wrap(\str_repeat('x', 384 - 64 - 2 + 1), self::keys()['rsa3072']['publicSpkiB64']);
    }

    /** 密钥解析失败：垃圾公钥包装抛明确错误；垃圾私钥解包返回 null（I7 模糊）。 */
    public function testWrapWithGarbagePublicKeyThrows(): void
    {
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('RSA 公钥解析失败');
        RsaOaep::wrap('x', 'not-a-key');
    }

    public function testUnwrapWithGarbagePrivateKeyReturnsNull(): void
    {
        $this->assertNull(RsaOaep::unwrap('AAAA', 'not-a-key'));
    }

    /** OAEP 容量边界：3072 位 k=384 → 明文恰 k-2·hLen-2=318 字节合法且可解。 */
    public function testWrapAcceptsMaxBoundaryPlaintext(): void
    {
        $keys = self::keys()['rsa3072'];
        $plain = str_repeat('M', 318);
        $this->assertSame(
            $plain,
            RsaOaep::unwrap(RsaOaep::wrap($plain, $keys['publicSpkiB64']), $keys['privatePkcs8B64']),
            'k-2*32-2 恰边界明文必须可包装可解包',
        );
    }
}
