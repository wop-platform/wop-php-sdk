<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\Aes256Gcm;
use Wop\Sdk\Base64Url;
use Wop\Sdk\CanonicalRequest;
use Wop\Sdk\ContentDigest;
use Wop\Sdk\DekPayload;
use Wop\Sdk\EncryptedEnvelope;
use Wop\Sdk\EncryptHeader;
use Wop\Sdk\RsaOaep;
use Wop\Sdk\RsaSigner;
use Wop\Sdk\SignHeader;
use Wop\Sdk\VerifyResult;

/**
 * 工具类实例化防线（private 构造器）与零散防御分支的定向覆盖。
 */
final class UtilityGuardTest extends TestCase
{
    /** private 构造器必须可直接执行（防 new 的空体构造）。 */
    public function testPrivateConstructorsAreCallable(): void
    {
        foreach ([
            Base64Url::class,
            CanonicalRequest::class,
            ContentDigest::class,
            EncryptedEnvelope::class,
            RsaOaep::class,
            RsaSigner::class,
            Aes256Gcm::class,
        ] as $class) {
            $ref = new \ReflectionClass($class);
            $ref->getConstructor()->invoke($ref->newInstanceWithoutConstructor());
            $this->addToAssertionCount(1);
        }
    }

    public function testEncryptHeaderEmptyStringIsL0(): void
    {
        $this->assertSame('L0', EncryptHeader::parse('')->level);
    }

    /** 非 dek 段被忽略（只识别 dek= 指令）。 */
    public function testEncryptHeaderIgnoresForeignDirectives(): void
    {
        $parsed = EncryptHeader::parse('L2;foo=bar;dek=xyz');
        $this->assertSame('L2', $parsed->level);
        $this->assertSame('xyz', $parsed->dek);
        $this->assertNull(EncryptHeader::parse('L2;foo=bar')->dek);
    }

    /** Suite：空白串（非空）也按解析类拒绝。 */
    public function testSuiteRejectsWhitespaceOnly(): void
    {
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('格式错误');
        \Wop\Sdk\Suite::parse(" \n\t ");
    }

    public function testSignHeaderBuildSingleHeader(): void
    {
        $this->assertSame(
            'WOP-RSA3072-SHA256 v1/10/only/s',
            SignHeader::build('WOP-RSA3072-SHA256', 10, ['only'], 's')
        );
    }

    public function testSignHeaderTryExtractBlankVariants(): void
    {
        $this->assertNull(SignHeader::tryExtractSecurityReq(''));
        $this->assertNull(SignHeader::tryExtractSecurityReq("\t"));
        $this->assertSame('X', SignHeader::tryExtractSecurityReq('X y/z'));
    }

    public function testSignHeaderParseBlankSignature(): void
    {
        $parsed = SignHeader::parse('WOP-RSA3072-SHA256 v1/10/a/b ');
        $this->assertSame('b', $parsed->signature);
    }

    public function testDekPayloadEncodeUnknownAlgPassthrough(): void
    {
        // alg 段是字符串字段：编码不校验白名单（族比对在 algMatches）
        $payload = new DekPayload('FUTURE-ALG', "\x01", "\x02");
        $this->assertSame('FUTURE-ALG$AQ$Ag', $payload->encode());
    }

    public function testVerifyResultFailCarriesReason(): void
    {
        $result = VerifyResult::fail('X');
        $this->assertFalse($result->ok);
        $this->assertNull($result->plaintext);
        $this->assertSame('X', $result->reason);
    }

    public function testAesDecryptEmptyCipherTag(): void
    {
        $this->assertNull(Aes256Gcm::decrypt('', str_repeat("\x00", 12), str_repeat("\x01", 32)));
    }

    public function testCanonicalBuildAllNulls(): void
    {
        $this->assertSame("\n\n\n\n", CanonicalRequest::build(null, ' ', null, null, null));
    }

    public function testCanonicalUrlencodeNullAndEmpty(): void
    {
        $this->assertSame('', CanonicalRequest::urlencode(null));
    }
}
