<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wop\Sdk\SignHeader;
use Wop\Sdk\WopException;

/** spec:F3 — 结构化 x-wop-sign：`<securityReq> v1/<expiredSeconds>/<signedHeaders>/<signature>`。 */
final class SignHeaderTest extends TestCase
{
    public function testBuild(): void
    {
        $this->assertSame(
            'WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-nonce/sig',
            SignHeader::build('WOP-RSA3072-SHA256', 1800, ['x-wop-appkey', 'x-wop-nonce'], 'sig')
        );
    }

    public function testParseRoundtrip(): void
    {
        $header = 'WOP-RSA4096-SHA256 v1/3600/x-wop-appkey;x-wop-content-digest;x-wop-nonce;x-wop-timestamp/ESw5IVyq';
        $parsed = SignHeader::parse($header);
        $this->assertSame('WOP-RSA4096-SHA256', $parsed->securityReq);
        $this->assertSame('v1', $parsed->protocolVersion);
        $this->assertSame(3600, $parsed->expiredSeconds);
        $this->assertSame(
            ['x-wop-appkey', 'x-wop-content-digest', 'x-wop-nonce', 'x-wop-timestamp'],
            $parsed->signedHeaders
        );
        $this->assertSame('ESw5IVyq', $parsed->signature);
    }

    public function testParseNormalizesSignedHeaderCaseAndSpaces(): void
    {
        $parsed = SignHeader::parse('WOP-RSA3072-SHA256 v1/10/ X-Wop-Nonce ; x-wop-timestamp /sig');
        $this->assertSame(['x-wop-nonce', 'x-wop-timestamp'], $parsed->signedHeaders);
    }

    public function testParseRequiresHeader(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('缺少 x-wop-sign');
        SignHeader::parse('');
    }

    /** spec:A2 结构化头负向量。 */
    #[DataProvider('malformedProvider')]
    public function testParseRejectsMalformed(string $header, string $message): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage($message);
        SignHeader::parse($header);
    }

    /** @return list<list<string>> */
    public static function malformedProvider(): array
    {
        return [
            ['WOP-RSA3072-SHA256', '格式错误'],
            ['WOP-RSA3072-SHA256 nospace-slash', '格式错误'],
            ['WOP-RSA3072-SHA256 v2/10/a/b', '签名协议版本'],
            ['WOP-RSA3072-SHA256 v1/abc/a/b', 'expiredSeconds'],
            ['WOP-RSA3072-SHA256 v1/0/a/b', 'expiredSeconds'],
            ['WOP-RSA3072-SHA256 v1/86401/a/b', 'expiredSeconds'],
            ['WOP-RSA3072-SHA256 v1/1800/;/sig', 'signedHeaders'],
            ['WOP-RSA3072-SHA256 v1/1800/a;b;', 'signature'],
        ];
    }

    public function testTryExtractSecurityReq(): void
    {
        $this->assertSame('WOP-RSA3072-SHA256', SignHeader::tryExtractSecurityReq('WOP-RSA3072-SHA256 v1/1/a/b'));
        $this->assertSame('WOP-RSA3072-SHA256', SignHeader::tryExtractSecurityReq('WOP-RSA3072-SHA256'));
        $this->assertNull(SignHeader::tryExtractSecurityReq(null));
        $this->assertNull(SignHeader::tryExtractSecurityReq('  '));
    }


    public function testParseRejectsNonNumericExpiredSeconds(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('expiredSeconds');
        SignHeader::parse('WOP-RSA3072-SHA256 v1/1800a/a/b');
    }

    public function testParseRejectsBlankSignatureOnly(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('signature');
        SignHeader::parse('WOP-RSA3072-SHA256 v1/10/a/  ');
    }
}
