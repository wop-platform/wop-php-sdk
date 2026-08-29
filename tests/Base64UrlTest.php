<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wop\Sdk\Base64Url;
use Wop\Sdk\WopException;

/** spec:F7 — 线上二进制编码 base64url 无填充，严格模式（拒 `=`、`+`、`/`）。 */
final class Base64UrlTest extends VectorCase
{
    public function testEncodeIsUnpaddedUrlSafe(): void
    {
        // 2 字节 → 3 字符；11 字节 → 15 字符（均无填充）
        $this->assertSame('AAEC', Base64Url::encode("\x00\x01\x02"));
        $this->assertSame('', Base64Url::encode(''));
        $raw = random_bytes(11);
        $encoded = Base64Url::encode($raw);
        $this->assertSame(15, strlen($encoded));
        $this->assertDoesNotMatchRegularExpression('/[=+\/]/', $encoded);
        $this->assertSame($raw, Base64Url::decode($encoded));
    }

    public function testDecodeRejectsPadding(): void
    {
        // spec:formatRules b64url-with-padding — "abc=" 必须拒绝
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('base64url');
        Base64Url::decode('abc=');
    }

    public function testDecodeRejectsIllegalChar(): void
    {
        // spec:formatRules b64url-illegal-char — "ab+c" 必须拒绝（标准字母表 + 不在 url 字母表）
        $this->expectException(WopException::class);
        Base64Url::decode('ab+c');
    }

    public function testDecodeRejectsSlash(): void
    {
        $this->expectException(WopException::class);
        Base64Url::decode('ab/c');
    }

    public function testDecodeRejectsInvalidLength(): void
    {
        $this->expectException(WopException::class);
        Base64Url::decode('abcde'); // mod 4 == 1，不可能合法
    }

    public function testDecodeVectorSignatureRoundtrip(): void
    {
        // 向量签名恒 512 字符（RSA3072）且解回 384 字节
        $vec = self::vector('signature', 'rsa3072-sign');
        $sig = Base64Url::decode($vec['expectedSigB64u']);
        $this->assertSame(384, strlen($sig));
        $this->assertSame($vec['expectedSigB64u'], Base64Url::encode($sig));
    }

    public function testDecodeRejectsNonCanonicalTrailingBitsTail2(): void
    {
        // spec:formatRules b64url-trailing-bits-noncanonical-2 语义锚（Go RawURLEncoding.Strict()）：
        // 'ab'：b=27 低 4 位 1011 非零 → 非规范，必须拒绝（base64_decode(strict) 宽容收下，旧实现即翻车点）
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('非规范尾随位');
        Base64Url::decode('ab');
    }

    public function testDecodeAcceptsCanonicalTail2And3(): void
    {
        // 合法无填充尾长正例：%4==2 尾字符低 4 位为零 / %4==3 尾字符低 2 位为零
        $this->assertSame("\x00", Base64Url::decode('AA'));
        $this->assertSame('Ma', Base64Url::decode('TWE'));
        $this->assertSame('i', Base64Url::decode('aQ'), "'i' 的规范 2 字符形式是 aQ（Q=16 低 4 位零），而非 ab");
        $this->assertSame(2, strlen(Base64Url::decode('abc')), "c=28 低 2 位零，'abc' 为规范 3 字符形式");
    }

    public function testDecodeTailsCoverDigitAndUrlSafeAlphabets(): void
    {
        // 尾字符为数字：'0'=52（110100）低 2 位零 → 规范 3 字符形态，2 字节 0x00 0x1D
        $this->assertSame("\x00\x1D", Base64Url::decode('AB0'));
        // 尾字符为 '-'(62)/'_'(63)：低 2 位（10/11）非零 → 必非规范，拒绝
        foreach (['AB-', 'AB_'] as $bad) {
            try {
                Base64Url::decode($bad);
                $this->fail('应拒绝: ' . $bad);
            } catch (WopException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /** spec:formatRules — b64url 规则全量循环消费（未知 id 即炸；canonical 两条钉解码字节）。 */
    #[DataProvider('b64UrlFormatRulesProvider')]
    public function testFormatRules(string $id, string $value, string $expect): void
    {
        switch ($id) {
            case 'b64url-trailing-bits-canonical-2':
                $this->assertSame('accept', $expect, $id . ' 向量自述须为 accept');
                $this->assertSame("\x00", Base64Url::decode($value), $id . ' → 1 字节 0x00');
                break;
            case 'b64url-trailing-bits-canonical-3':
                $this->assertSame('accept', $expect, $id . ' 向量自述须为 accept');
                $this->assertSame('Ma', Base64Url::decode($value), $id . ' → 2 字节 0x4D 0x61');
                break;
            case 'b64url-with-padding':
            case 'b64url-illegal-char':
            case 'b64url-trailing-bits-noncanonical-2':
            case 'b64url-trailing-bits-noncanonical-3':
                $this->assertSame('reject', $expect, $id . ' 向量自述须为 reject');
                $this->expectException(WopException::class);
                Base64Url::decode($value);
                break;
            default:
                $this->fail('未预期 formatRules 向量（未知 id，须同步消费逻辑）: ' . $id);
        }
    }

    /** @return list<list<string>> */
    public static function b64UrlFormatRulesProvider(): array
    {
        $cases = [];
        foreach (self::formatRulesAll() as $rule) {
            if (!\str_starts_with((string) $rule['id'], 'b64url-')) {
                continue; // header- 规则由 ContentDigestTest 消费
            }
            $cases[] = [$rule['id'], $rule['value'], $rule['expect']];
        }
        return $cases;
    }

    /** spec:formatRules 三件套之"条数哨兵"——真源增删规则时强制同步消费。 */
    public function testFormatRulesCountSentinel(): void
    {
        $this->assertCount(12, self::vectorList('formatRules'), 'formatRules 应为 12 条（与真源 commit 18836a2 对齐）');
    }

    /** 异常消息不得携带原始输入（防 DEK 等密钥材料经日志泄露）。 */
    public function testDecodeErrorMessagesDoNotLeakInput(): void
    {
        foreach (['abc=' => 'padding', 'ab+c' => 'illegal', 'abcde' => 'length', 'ab' => 'trailing', 'aE' => 'trailing-2', 'TWF' => 'trailing-3'] as $bad => $note) {
            try {
                Base64Url::decode($bad);
                $this->fail("应拒绝（{$note}）: " . $bad);
            } catch (WopException $e) {
                $this->assertStringNotContainsString($bad, $e->getMessage(), "异常消息不得内嵌输入（{$note}）");
            }
        }
    }

    /**
     * decodeIndex（私有纯函数）字母表映射表驱动：钉死各分支边界字符
     * （A/Z/a/z/0/9/-/_）与算术偏移——D1 尾随位校验的正确性根基。
     */
    public function testDecodeIndexAlphabetMapping(): void
    {
        $method = new \ReflectionMethod(Base64Url::class, 'decodeIndex');
        foreach ([
            'A' => 0, 'B' => 1, 'Z' => 25,
            'a' => 26, 'b' => 27, 'z' => 51,
            '0' => 52, '1' => 53, '9' => 61,
            '-' => 62, '_' => 63,
        ] as $char => $index) {
            $this->assertSame($index, $method->invoke(null, $char), "decodeIndex('{$char}')");
        }
    }
}
