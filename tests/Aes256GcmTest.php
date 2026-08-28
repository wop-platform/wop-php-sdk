<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\Aes256Gcm;

/**
 * spec:F5/F4(D10) — AES-256-GCM，密文 = ciphertext||tag 尾拼；向量字节级。
 */
final class Aes256GcmTest extends VectorCase
{
    public function testDecryptMatchesVector(): void
    {
        $vec = self::vector('messageEncrypt', 'aesgcm-encrypt');
        $plain = Aes256Gcm::decrypt(
            self::b64uDecode($vec['cipherTagB64u']),
            self::b64uDecode($vec['ivB64u']),
            self::b64uDecode($vec['keyB64u'])
        );
        $this->assertSame(self::b64uDecode($vec['plaintextB64u']), $plain);
    }

    public function testEncryptWithFixedIvMatchesVector(): void
    {
        $vec = self::vector('messageEncrypt', 'aesgcm-encrypt');
        $result = Aes256Gcm::encrypt(
            self::b64uDecode($vec['plaintextB64u']),
            self::b64uDecode($vec['keyB64u']),
            self::b64uDecode($vec['ivB64u'])
        );
        $this->assertSame(self::b64uDecode($vec['cipherTagB64u']), $result->cipherTag);
        $this->assertSame(self::b64uDecode($vec['ivB64u']), $result->iv, '固定 IV 时原样透传');
    }

    public function testEncryptGeneratesRandomIvWhenOmitted(): void
    {
        $vec = self::vector('messageEncrypt', 'aesgcm-encrypt');
        $a = Aes256Gcm::encrypt('hello', str_repeat("\x01", 32));
        $b = Aes256Gcm::encrypt('hello', str_repeat("\x01", 32));
        $this->assertSame(12, strlen($a->iv));
        $this->assertNotSame($a->cipherTag, $b->cipherTag, 'CSPRNG IV 下同明文密文必不同（I4）');
        $this->assertSame('hello', Aes256Gcm::decrypt($a->cipherTag, $a->iv, str_repeat("\x01", 32)));
    }

    /** A2 tamper：GCM tag 失败必须拒绝。 */
    public function testDecryptRejectsTamperedTag(): void
    {
        $vec = self::vector('messageEncrypt', 'aesgcm-encrypt');
        $ct = self::b64uDecode($vec['cipherTagB64u']);
        $ct[strlen($ct) - 1] = $ct[strlen($ct) - 1] ^ "\x01";
        $this->assertNull(Aes256Gcm::decrypt($ct, self::b64uDecode($vec['ivB64u']), self::b64uDecode($vec['keyB64u'])));
    }

    public function testDecryptRejectsWrongKey(): void
    {
        $vec = self::vector('messageEncrypt', 'aesgcm-encrypt');
        $this->assertNull(Aes256Gcm::decrypt(
            self::b64uDecode($vec['cipherTagB64u']),
            self::b64uDecode($vec['ivB64u']),
            str_repeat("\x09", 32)
        ));
    }

    public function testKeyLengthEnforced(): void
    {
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('密钥长度');
        Aes256Gcm::encrypt('x', str_repeat("\x01", 16));
    }
}
