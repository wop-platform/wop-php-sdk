<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\RequestId;
use Wop\Sdk\WopConfig;
use Wop\Sdk\WopClient;
use Wop\Sdk\WopException;

/** spec:wop-sdk-spec 附录 I — x-wop-request-id 透传头（I1 恒不入签 / I2 值校验 / I3 缺省生成与日志）。 */
final class WopClientRequestIdTest extends VectorCase
{
    private WopClient $client;

    protected function setUp(): void
    {
        $keys = self::keys();
        $this->client = new WopClient(new WopConfig(
            appKey: 'app_10012481831',
            securityReq: 'WOP-RSA3072-SHA256',
            privateKey: $keys['rsa3072']['privatePkcs8B64'],
            peerPublicKey: $keys['rsa3072']['publicSpkiB64'],
        ));
    }

    public function testExplicitValueTrimmedUpstream(): void
    {
        $draft = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, '  req-001  ');
        self::assertSame('req-001', $draft->header('x-wop-request-id'));
    }

    public function testNeverSignedAndSignBytesUnchanged(): void
    {
        $withId = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, 'req-001');
        $without = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n');
        $names = explode(';', explode('/', explode(' ', (string) $withId->header('x-wop-sign'))[1])[2]);
        self::assertNotContains('x-wop-request-id', $names, '透传头不得进入 signedHeaders（附录 I/I1）');
        self::assertSame($without->header('x-wop-sign'), $withId->header('x-wop-sign'), '带/不带透传头签名字节同值');
    }

    public function testDefaultGeneratedUuid32AndFresh(): void
    {
        $a = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n');
        $b = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $a->header('x-wop-request-id'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $b->header('x-wop-request-id'));
        self::assertNotSame($a->header('x-wop-request-id'), $b->header('x-wop-request-id'));
        // 空格 trim 后为空 → 视为未设置，走缺省生成（\t/\n 属控制字符，trim 前扫描即拒）
        $blank = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, '   ');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $blank->header('x-wop-request-id'));
    }

    /** @return list<list<string>> */
    public static function controlCharProvider(): array
    {
        return [
            ["a\nb"], ["a\rb"], ["a\x00b"], ["a\x7Fb"], ["a\tb"], ["\nlead"], ["trail\r"], [" \t "], ["\x00"], ["\x7F"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('controlCharProvider')]
    public function testControlCharsRejectedPreTrim(string $bad): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('控制字符');
        $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, $bad);
    }

    public function testLengthMeasuredInUtf8Bytes(): void
    {
        $ok = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, str_repeat('x', 128));
        self::assertSame(str_repeat('x', 128), $ok->header('x-wop-request-id'));
        try {
            $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, str_repeat('x', 129));
            self::fail('129 字节应拒绝');
        } catch (WopException $e) {
            self::assertStringContainsString('实际 129', $e->getMessage());
        }
        $cjk = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, str_repeat('标', 42));
        self::assertSame(str_repeat('标', 42), $cjk->header('x-wop-request-id'));
        $this->expectException(WopException::class);
        $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, str_repeat('标', 43));
    }

    public function testOutboundLogContainsFinalValue(): void
    {
        $lines = [];
        $prev = WopClient::$outboundLogger;
        WopClient::$outboundLogger = static function (string $line) use (&$lines): void { $lines[] = $line; };
        try {
            $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, 'logreq001');
        } finally {
            WopClient::$outboundLogger = $prev;
        }
        self::assertCount(1, $lines);
        self::assertStringContainsString('x-wop-request-id=logreq001 GET /p', $lines[0]);
    }

    public function testInjectedGeneratorHonored(): void
    {
        $prev = RequestId::$generator;
        RequestId::$generator = static fn (): string => 'gen-anchor-001';
        try {
            $draft = $this->client->buildRequest('POST', '/p', '{"k":1}', 'L2', 1, 'n');
        } finally {
            RequestId::$generator = $prev;
        }
        self::assertSame('gen-anchor-001', $draft->header('x-wop-request-id'));
    }
}
