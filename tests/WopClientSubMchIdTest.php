<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\CanonicalRequest;
use Wop\Sdk\Config\WopSdkConfig;
use Wop\Sdk\RsaSigner;
use Wop\Sdk\SignHeader;
use Wop\Sdk\Transport\TransportInterface;
use Wop\Sdk\Transport\TransportResponse;
use Wop\Sdk\WopClient;
use Wop\Sdk\WopConfig;
use Wop\Sdk\WopException;

/** spec:ISV D-13 — x-wop-sub-mch-id 子商户身份头（存在即入签 / 值校验 / 缺省零回归 AC-20）。 */
final class WopClientSubMchIdTest extends VectorCase
{
    private const PATH = '/gateway/logistics.order.query';
    private const NONCE = '0123456789abcdef0123456789abcdef';

    private WopClient $client;

    protected function setUp(): void
    {
        $keys = self::keys()['rsa3072'];
        $this->client = new WopClient(new WopConfig(
            appKey: 'app_10012481831',
            securityReq: 'WOP-RSA3072-SHA256',
            privateKey: $keys['privatePkcs8B64'],
            peerPublicKey: $keys['publicSpkiB64'],
        ));
    }

    /** L0 有 body：子商户头写入并入签（digest 同在）。 */
    public function testHeaderSignedL0WithBody(): void
    {
        $draft = $this->client->buildRequest('POST', self::PATH, '{"k":1}', 'L0', 1774340000000, self::NONCE, null, null, 'PLF-SUB-001');

        self::assertSame('PLF-SUB-001', $draft->header('x-wop-sub-mch-id'));
        $sign = SignHeader::parse((string) $draft->header('x-wop-sign'));
        self::assertSame([
            'x-wop-appkey', 'x-wop-content-digest', 'x-wop-nonce', 'x-wop-sub-mch-id', 'x-wop-timestamp',
        ], $sign->signedHeaders);
        self::assertTrue($this->verifyDraft($draft));
    }

    /** L0 无 body：digest 缺席，子商户头仍入签。 */
    public function testHeaderSignedL0WithoutBody(): void
    {
        $draft = $this->client->buildRequest('GET', self::PATH, null, 'L0', 1774340000000, self::NONCE, null, null, 'PLF-SUB-001');

        $sign = SignHeader::parse((string) $draft->header('x-wop-sign'));
        self::assertSame(['x-wop-appkey', 'x-wop-nonce', 'x-wop-sub-mch-id', 'x-wop-timestamp'], $sign->signedHeaders);
        self::assertTrue($this->verifyDraft($draft));
    }

    /** L2：加密头 + 子商户头同时在 signedHeaders。 */
    public function testHeaderSignedL2(): void
    {
        $draft = $this->client->buildRequest('POST', self::PATH, '{"amount":100}', 'L2', 1774340000000, self::NONCE, null, null, 'PLF-SUB-001');

        $sign = SignHeader::parse((string) $draft->header('x-wop-sign'));
        self::assertSame([
            'x-wop-appkey', 'x-wop-content-digest', 'x-wop-encrypt', 'x-wop-nonce', 'x-wop-sub-mch-id', 'x-wop-timestamp',
        ], $sign->signedHeaders);
        self::assertTrue($this->verifyDraft($draft));
    }

    /** AC-20 零回归：未传与纯空白 → 头缺席，签名逐字节同存量行为。 */
    public function testAbsentAndBlankKeepHeadersByteIdentical(): void
    {
        $plain = $this->client->buildRequest('POST', self::PATH, '{"k":1}', 'L0', 1774340000000, self::NONCE, null, 'req-001');
        $empty = $this->client->buildRequest('POST', self::PATH, '{"k":1}', 'L0', 1774340000000, self::NONCE, null, 'req-001', '');
        $blank = $this->client->buildRequest('POST', self::PATH, '{"k":1}', 'L0', 1774340000000, self::NONCE, null, 'req-001', '   ');

        self::assertNull($plain->header('x-wop-sub-mch-id'));
        self::assertNull($empty->header('x-wop-sub-mch-id'));
        self::assertNull($blank->header('x-wop-sub-mch-id'));
        self::assertSame($plain->headers, $empty->headers);
        self::assertSame($plain->headers, $blank->headers);
    }

    /** 首尾空白 trim 后上行（与网关身份查询 trim 一致）。 */
    public function testLeadingTrailingWhitespaceTrimmed(): void
    {
        $draft = $this->client->buildRequest('GET', self::PATH, null, 'L0', 1774340000000, self::NONCE, null, null, '  PLF-SUB-001  ');
        self::assertSame('PLF-SUB-001', $draft->header('x-wop-sub-mch-id'));
    }

    /** @return list<list<string>> */
    public static function nonPrintableProvider(): array
    {
        return [
            ["a\nb"], ["a\rb"], ["a\x00b"], ["a\x7Fb"], ["a\tb"], ["\tlead"], ["trail\r"], ['PLF中文'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('nonPrintableProvider')]
    public function testNonPrintableAsciiRejected(string $bad): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('可打印 ASCII');
        $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, null, $bad);
    }

    /** 内部空白：网关 canonical trimall 折叠空白，身份查询只 trim → 一一对应被破坏。 */
    public function testInternalWhitespaceRejected(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('内部空白');
        $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, null, 'PLF SUB');
    }

    public function testLengthLimit(): void
    {
        $len128 = str_repeat('a', 128);
        $ok = $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, null, $len128);
        self::assertSame($len128, $ok->header('x-wop-sub-mch-id'));

        $this->expectException(WopException::class);
        $this->expectExceptionMessage('实际 129');
        $this->client->buildRequest('GET', '/p', null, 'L0', 1, 'n', null, null, str_repeat('a', 129));
    }

    /** execute 路径同样写入并入签子商户头。 */
    public function testExecuteCarriesAndSignsHeader(): void
    {
        $transport = new CapturingTransport();
        $keys = self::keys()['rsa3072'];
        $client = WopClient::fromConfig(WopSdkConfig::builder()
            ->appKey('app_10012481831')
            ->suite('WOP-RSA3072-SHA256')
            ->merchantPrivateKey($keys['privatePkcs8B64'])
            ->platformPublicKey($keys['publicSpkiB64'])
            ->serverRoot('https://gw.example.com/gateway')
            ->transport($transport)
            ->build());

        $result = $client->execute('POST', self::PATH, '{}', 'L0', null, 'PLF-SUB-001');

        // 空响应头 → 入向验签失败但不抛（F6/I7）
        self::assertFalse($result->ok);
        self::assertNotNull($transport->headers);
        $headers = [];
        foreach ($transport->headers as $line) {
            [$name, $value] = explode(': ', $line, 2);
            $headers[$name] = $value;
        }
        self::assertSame('PLF-SUB-001', $headers['x-wop-sub-mch-id']);
        $sign = SignHeader::parse($headers['x-wop-sign']);
        self::assertContains('x-wop-sub-mch-id', $sign->signedHeaders);
        $canonical = CanonicalRequest::build(
            'v1/1800',
            'POST',
            self::PATH,
            '',
            CanonicalRequest::canonicalHeaders(array_intersect_key($headers, array_flip($sign->signedHeaders)))
        );
        self::assertTrue(RsaSigner::verify($canonical, $sign->signature, $keys['publicSpkiB64']));
    }

    private function verifyDraft(\Wop\Sdk\RequestDraft $draft): bool
    {
        $sign = SignHeader::parse((string) $draft->header('x-wop-sign'));
        $canonical = CanonicalRequest::build(
            'v1/1800',
            $draft->method,
            $draft->path,
            '',
            CanonicalRequest::canonicalHeaders(array_intersect_key($draft->headers, array_flip($sign->signedHeaders)))
        );
        return RsaSigner::verify($canonical, $sign->signature, self::keys()['rsa3072']['publicSpkiB64']);
    }
}

/** 捕获出向头行并返回空 200 响应（execute 入向验签必然失败但返回结果对象）。 */
final class CapturingTransport implements TransportInterface
{
    /** @var list<string>|null */
    public ?array $headers = null;

    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        unset($method, $url, $body);
        $this->headers = $headers;
        return new TransportResponse(200, [], '');
    }
}
