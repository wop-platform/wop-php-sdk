<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Wop\Sdk\ContentDigest;
use Wop\Sdk\Suite;
use Wop\Sdk\WopException;

/**
 * spec:F4/D2 — `alg 小写hex` 恰一空格；无 body 缺席；formatRules 全量负向量。
 */
final class ContentDigestTest extends VectorCase
{
    public function testBuildSha256FromVector(): void
    {
        $vec = self::vector('digest', 'digest-sha256');
        $suite = Suite::parse('WOP-RSA3072-SHA256');
        $this->assertSame($vec['expectedHeader'], ContentDigest::build($vec['input'], $suite));
    }

    public function testDigestHexIsLowercase(): void
    {
        $vec = self::vector('digest', 'digest-sha256');
        $this->assertSame($vec['expectedHex'], ContentDigest::sha256Hex($vec['input']));
    }

    /** spec:formatRules — 向量中每条 header 规则逐一判定。 */
    #[DataProvider('formatRulesProvider')]
    public function testFormatRules(string $id, string $value, string $expect, ?string $suite): void
    {
        $parsedSuite = $suite === null ? null : Suite::parse($suite);
        if ($expect === 'accept') {
            $this->assertTrue(ContentDigest::validate($value, $parsedSuite), $id);
        } else {
            $this->expectException(WopException::class);
            ContentDigest::validate($value, $parsedSuite);
        }
    }

    /** @return list<list<string|null>> */
    public static function formatRulesProvider(): array
    {
        $cases = [];
        $skippedSm2 = 0;
        foreach (self::formatRulesAll() as $rule) {
            if (!str_starts_with((string) $rule['id'], 'header-')) {
                continue; // b64url 规则由 Base64UrlTest 消费
            }
            // Q7：PHP 首版 SM 套件不可装配（Suite::parse 拒绝），header-sm2-ok 的
            // 正消费留待 SM 支持版本；跨族 header-crossfamily 负向量正常消费。
            // 跳过必须恰好是这一条（skippedSm2 哨兵），SM 支持落地后此豁免即失效须更新
            if (($rule['suite'] ?? null) === 'WOP-SM2-SM3' && $rule['expect'] === 'accept') {
                $skippedSm2++;
                continue;
            }
            $cases[] = [$rule['id'], $rule['value'], $rule['expect'], $rule['suite'] ?? null];
        }
        if ($skippedSm2 !== 1) {
            throw new RuntimeException('header-sm2-ok Q7 豁免数量异常（须恰好 1 条）: ' . $skippedSm2);
        }
        return $cases;
    }

    public function testMatchesWireBytes(): void
    {
        $vec = self::vector('digest', 'digest-sha256');
        $this->assertTrue(ContentDigest::matches($vec['expectedHeader'], $vec['input']));
        $this->assertFalse(ContentDigest::matches($vec['expectedHeader'], $vec['input'] . 'x'));
        $this->assertFalse(ContentDigest::matches('', 'any'));
    }

    public function testValidateRejectsEmptyLabelAndHex(): void
    {
        foreach ([
            ' 4cf7ab3bcefc20c8d6116d4ce9a3fdfb0d60ba5391472d7bffcf159da9e033ca' => '空标签',
            'sha-256 ' => '空 hex',
            'sha-256' => '无分隔',
            'sha-256 4cf7ab3bcefc20c8d6116d4ce9a3fdfb0d60ba5391472d7bffcf159da9e033ca extra' => '三段',
        ] as $value => $note) {
            try {
                ContentDigest::validate($value);
                $this->fail("应拒绝（$note）: " . $value);
            } catch (WopException) {
                $this->addToAssertionCount(1); // 期望拒绝路径
            }
        }
    }

    public function testMatchesRejectsMalformedHeaderWithoutThrowing(): void
    {
        $this->assertFalse(ContentDigest::matches('not-a-digest', 'x'));
        $this->assertFalse(ContentDigest::matches('sha-256 NOTHEX', 'x'));
    }

    /** 解析类负向量文案钉死（格式/族不符/摘要格式三分支）。 */
    public function testValidateRejectMessageTexts(): void
    {
        $suite = Suite::parse('WOP-RSA3072-SHA256');
        foreach ([
            'sha-256' => '应为',
            'sha-256  ' => '应为', // 双空格：三段 explode 走 count 分支（非空段分支）
            'sm3 ' . str_repeat('a', 64) => '算法标签与套件族不符',
            'sha-256 ' . strtoupper(str_repeat('a', 64)) => '摘要格式错误',
        ] as $value => $fragment) {
            try {
                ContentDigest::validate($value, $suite);
                $this->fail("应拒绝: {$value}");
            } catch (WopException $e) {
                $this->assertStringContainsString($fragment, $e->getMessage(), $value);
            }
        }
    }
}
