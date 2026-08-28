<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\CanonicalRequest;

/**
 * spec:F2 — canonicalRequest 5 段 `\n`；header 值 Java-URLEncoder 语义（空格→%20）。
 * 与 gateway CanonicalRequestBuilder 行为逐条对齐（同一参考实现的测试用例移植）。
 */
final class CanonicalRequestTest extends TestCase
{
    public function testUrlencodeFollowsJavaUrlEncoderSemantics(): void
    {
        // 空格 → %20（而非 '+'）
        $this->assertSame('a%20b', CanonicalRequest::urlencode('a b'));
        // '+' → %2B
        $this->assertSame('2026-08-18T15%3A30%3A00%2B08%3A00', CanonicalRequest::urlencode('2026-08-18T15:30:00+08:00'));
        // ';' → %3B、'=' → %3D（x-wop-encrypt 值场景）
        $this->assertSame('L2%3Bdek%3Dabc', CanonicalRequest::urlencode('L2;dek=abc'));
        // Java URLEncoder 保留 '.'、'-'、'*'、'_'；编码 '~'、'!'、"'"、'('、')'
        $this->assertSame('.-*_aZ0', CanonicalRequest::urlencode('.-*_aZ0'));
        $this->assertSame('%7E%21%27%28%29', CanonicalRequest::urlencode("~!'()"));
        // 中文 → UTF-8 百分号编码
        $this->assertSame('%E8%B7%A8%E8%AF%AD%E8%A8%80', CanonicalRequest::urlencode('跨语言'));
        $this->assertSame('', CanonicalRequest::urlencode(''));
    }

    public function testTrimallCollapsesWhitespace(): void
    {
        $this->assertSame('a b c', CanonicalRequest::trimall('   a   b   c  '));
        $this->assertSame('"a b c"', CanonicalRequest::trimall('  "a   b   c"  '));
        $this->assertSame('', CanonicalRequest::trimall(null));
        $this->assertSame('', CanonicalRequest::trimall(''));
    }

    public function testCanonicalHeadersLowercaseSortAndEncode(): void
    {
        // 故意乱序 + 大写 + 含空格值
        $headers = [
            'X-Wop-Timestamp' => '1774340000000',
            'My-Header1' => "  a   b c ",
            'x-wop-appkey' => 'app_10012481831',
        ];

        $this->assertSame(
            "my-header1:a%20b%20c\nx-wop-appkey:app_10012481831\nx-wop-timestamp:1774340000000",
            CanonicalRequest::canonicalHeaders($headers)
        );
    }

    public function testCanonicalHeadersEmptyInput(): void
    {
        $this->assertSame('', CanonicalRequest::canonicalHeaders([]));
        $this->assertSame('', CanonicalRequest::canonicalHeaders(null));
    }

    public function testBuildProducesFiveSegments(): void
    {
        $canonical = CanonicalRequest::build('v1/1800', 'post', '/gateway/logistics.order.query', '', 'x-wop-appkey:app_1');

        $this->assertSame(
            "v1/1800\nPOST\n/gateway/logistics.order.query\n\nx-wop-appkey:app_1",
            $canonical
        );
        $this->assertCount(5, explode("\n", $canonical));
    }

    public function testBuildNullSegmentsBecomeEmptyStrings(): void
    {
        $this->assertSame("\n\n\n\n", CanonicalRequest::build(null, null, null, null, null));
        $this->assertSame("\nGET\n\n\n", CanonicalRequest::build(null, ' get ', null, null, null));
    }
}
