<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wop\Sdk\Suite;
use Wop\Sdk\WopException;

/** spec:F1 — securityReq 解析；SM 套件首版必须明确拒绝（Q7）。 */
final class SuiteTest extends TestCase
{
    public function testParseRsa3072(): void
    {
        $suite = Suite::parse('WOP-RSA3072-SHA256');
        $this->assertSame('WOP-RSA3072-SHA256', $suite->securityReq);
        $this->assertSame('RSA', $suite->keyAlgorithm);
        $this->assertSame(3072, $suite->keyLength);
        $this->assertSame('sha-256', $suite->digestLabel);
        $this->assertSame('AES-256-GCM', $suite->dekAlg);
    }

    public function testParseRsa4096(): void
    {
        $suite = Suite::parse('WOP-RSA4096-SHA256');
        $this->assertSame(4096, $suite->keyLength);
        $this->assertSame('RSA', $suite->keyAlgorithm);
        $this->assertSame('sha-256', $suite->digestLabel);
    }

    public function testParseSm2Sm3IsRejectedWithRoadmapMessage(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('SM2-SM3 套件暂未支持，见 README 路线图');
        Suite::parse('WOP-SM2-SM3');
    }

    /** spec:F1 跨族组合（spec §2.3）必须拒绝，且不属于"暂未支持"语义。 */
    #[DataProvider('crossFamilyProvider')]
    public function testCrossFamilyRejected(string $securityReq): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('不支持的算法组合');
        Suite::parse($securityReq);
    }

    /** @return list<list<string>> */
    public static function crossFamilyProvider(): array
    {
        return [
            ['WOP-RSA3072-SM3'],
            ['WOP-RSA4096-SM3'],
            ['WOP-SM2-SHA256'],
        ];
    }

    /** spec:F1 解析类失败：空值/前缀错/段数错。 */
    #[DataProvider('malformedProvider')]
    public function testMalformedRejected(string $securityReq): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('格式错误');
        Suite::parse($securityReq);
    }

    /** @return list<list<string>> */
    public static function malformedProvider(): array
    {
        return [
            [''],
            ['   '],
            ['RSA3072-SHA256'],
            ['WOP-RSA3072'],
            ['WOP-RSA3072-SHA256-EXTRA'],
            ['wop-rsa3072-sha256'],
        ];
    }

    /** spec:F1 支持类失败：算法标识不在支持列表。 */
    #[DataProvider('unknownAlgorithmProvider')]
    public function testUnknownAlgorithmRejected(string $securityReq): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('不支持的算法组合');
        Suite::parse($securityReq);
    }

    /** @return list<list<string>> */
    public static function unknownAlgorithmProvider(): array
    {
        return [
            ['WOP-RSA2048-SHA256'],
            ['WOP-RSA3072-SHA384'],
            ['WOP-DSA-SHA256'],
        ];
    }

    /** F1 两类支持性失败的文案分界：未知算法 vs 国际/国密跨族。 */
    public function testUnknownAlgorithmAndCrossFamilyMessageDistinction(): void
    {
        foreach (['WOP-RSA3072-SM3', 'WOP-SM2-SHA256'] as $crossFamily) {
            try {
                Suite::parse($crossFamily);
                $this->fail("跨族应拒绝: {$crossFamily}");
            } catch (WopException $e) {
                $this->assertStringContainsString('跨族禁止', $e->getMessage(), $crossFamily);
            }
        }
        try {
            Suite::parse('WOP-RSA2048-SHA256');
            $this->fail('未知算法应拒绝');
        } catch (WopException $e) {
            $this->assertStringContainsString('不支持的算法组合: ', $e->getMessage());
            $this->assertStringNotContainsString('跨族', $e->getMessage(), '未知算法不得误报跨族');
        }
    }
}
