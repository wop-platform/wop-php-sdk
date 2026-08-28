<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\RsaSigner;

/**
 * spec:F3/A1 — SHA256withRSA（PKCS#1 v1.5，phpseclib≥3），向量字节级断言。
 */
final class RsaSignerTest extends VectorCase
{
    public function testSignRsa3072MatchesVectorByteForByte(): void
    {
        $vec = self::vector('signature', 'rsa3072-sign');
        $sig = RsaSigner::sign($vec['message'], self::keys()['rsa3072']['privatePkcs8B64']);
        $this->assertSame($vec['expectedSigB64u'], $sig);
        $this->assertSame(512, strlen($sig), 'RSA3072 签名 base64url 恒 512 字符');
    }

    public function testSignRsa4096MatchesVectorByteForByte(): void
    {
        $vec = self::vector('signature', 'rsa4096-sign');
        $sig = RsaSigner::sign($vec['message'], self::keys()['rsa4096']['privatePkcs8B64']);
        $this->assertSame($vec['expectedSigB64u'], $sig);
        $this->assertSame(683, strlen($sig), 'RSA4096 签名 base64url 恒 683 字符');
    }

    public function testVerifyVectorSignatures(): void
    {
        foreach (['rsa3072-sign', 'rsa4096-sign'] as $id) {
            $vec = self::vector('signature', $id);
            $this->assertTrue(RsaSigner::verify(
                $vec['message'],
                $vec['expectedSigB64u'],
                self::keys()[$vec['key']]['publicSpkiB64']
            ), $id);
        }
    }

    public function testVerifyRejectsTamperedMessage(): void
    {
        $vec = self::vector('signature', 'rsa3072-sign');
        $this->assertFalse(RsaSigner::verify(
            $vec['message'] . 'x',
            $vec['expectedSigB64u'],
            self::keys()['rsa3072']['publicSpkiB64']
        ));
    }

    public function testVerifyRejectsTamperedSignature(): void
    {
        $vec = self::vector('signature', 'rsa3072-sign');
        $tampered = substr($vec['expectedSigB64u'], 0, -1) . 'A';
        $this->assertFalse(RsaSigner::verify($vec['message'], $tampered, self::keys()['rsa3072']['publicSpkiB64']));
        // spec:A2 非 base64url 输入直接拒绝
        $this->assertFalse(RsaSigner::verify($vec['message'], '!!!not-base64!!!', self::keys()['rsa3072']['publicSpkiB64']));
        $this->assertFalse(RsaSigner::verify($vec['message'], 'abc=', self::keys()['rsa3072']['publicSpkiB64']));
    }

    public function testVerifyRejectsWrongPublicKey(): void
    {
        $vec = self::vector('signature', 'rsa3072-sign');
        $this->assertFalse(RsaSigner::verify(
            $vec['message'],
            $vec['expectedSigB64u'],
            self::keys()['rsa4096']['publicSpkiB64']
        ));
    }

    public function testSignAcceptsPemWrappedKeys(): void
    {
        // D12：PEM 仅作 Base64 单行的可选包装，两种入参等价
        $vec = self::vector('signature', 'rsa3072-sign');
        $b64 = self::keys()['rsa3072']['privatePkcs8B64'];
        $lines = str_split($b64, 64);
        $pem = "-----BEGIN PRIVATE KEY-----\n" . implode("\n", $lines) . "\n-----END PRIVATE KEY-----\n";
        $this->assertSame($vec['expectedSigB64u'], RsaSigner::sign($vec['message'], $pem));

        $pubPem = "-----BEGIN PUBLIC KEY-----\n" . implode("\n", str_split(self::keys()['rsa3072']['publicSpkiB64'], 64)) . "\n-----END PUBLIC KEY-----\n";
        $this->assertTrue(RsaSigner::verify($vec['message'], $vec['expectedSigB64u'], $pubPem));
    }

    /** 密钥解析失败：垃圾私钥加签抛明确 WopException，垃圾公钥验签降级 false（I7）。 */
    public function testKeyParseFailures(): void
    {
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('RSA 私钥解析失败');
        RsaSigner::sign('x', 'not-a-key');
    }

    public function testVerifyWithGarbagePublicKeyReturnsFalse(): void
    {
        $vec = self::vector('signature', 'rsa3072-sign');
        $this->assertFalse(RsaSigner::verify($vec['message'], $vec['expectedSigB64u'], 'not-a-key'));
    }
}
