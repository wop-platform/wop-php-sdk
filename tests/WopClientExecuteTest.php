<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\Config\WopConfigLoader;
use Wop\Sdk\Config\WopSdkConfig;
use Wop\Sdk\Transport\TransportInterface;
use Wop\Sdk\Transport\TransportResponse;
use Wop\Sdk\WopClient;
use Wop\Sdk\WopException;
use Wop\Sdk\WopGatewayResponseException;

/** config-spec P0：defaultClient / fromConfig / resetDefault / execute。 */
final class WopClientExecuteTest extends VectorCase
{
    private const PATH = '/gateway/logistics.order.query';

    protected function setUp(): void
    {
        WopClientConfigTestHelper::resetDefault();
    }

    protected function tearDown(): void
    {
        WopClientConfigTestHelper::resetDefault();
    }

    public function testFromConfigBuilderEquivalentToJson(): void
    {
        $keys = self::keys()['rsa3072'];
        $config = WopSdkConfig::builder()
            ->appKey('app_10012481831')
            ->suite('WOP-RSA3072-SHA256')
            ->merchantPrivateKey($keys['privatePkcs8B64'])
            ->platformPublicKey($keys['publicSpkiB64'])
            ->serverRoot('https://gw.example.com/gateway')
            ->transport(new StubTransport(static fn (): TransportResponse => new TransportResponse(200, [], '')))
            ->build();

        $client = WopClient::fromConfig($config);
        $this->assertInstanceOf(WopClient::class, $client);
    }

    public function testExecuteWithoutTransportConfiguredFails(): void
    {
        $client = new WopClient(new \Wop\Sdk\WopConfig(
            'app',
            'WOP-RSA3072-SHA256',
            self::keys()['rsa3072']['privatePkcs8B64'],
            self::keys()['rsa3072']['publicSpkiB64'],
        ));
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('未配置传输，无法 execute');
        $client->execute('POST', self::PATH, '{"a":1}');
    }

    public function testExecuteRejectsInvalidPath(): void
    {
        $client = $this->clientWithTransport(new StubTransport(static fn (): TransportResponse => new TransportResponse(200, [], '')));
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('path 不得 // 开头');
        $client->execute('POST', '//attacker.example/path', '{}');
    }

    public function testExecuteNon2xxThrowsGatewayResponseException(): void
    {
        $client = $this->clientWithTransport(new StubTransport(static fn (): TransportResponse => new TransportResponse(
            502,
            [],
            'bad-gateway'
        )));
        try {
            $client->execute('POST', self::PATH, '{"a":1}');
            $this->fail('应抛出网关响应异常');
        } catch (WopGatewayResponseException $e) {
            $this->assertSame(502, $e->statusCode);
            $this->assertSame('bad-gateway', $e->body);
            $this->assertSame('WOP 网关返回 HTTP 502（响应体 11 字节）', $e->getMessage());
        }
    }

    public function testExecuteHappyPathVerifiesResponse(): void
    {
        $transport = new StubTransport(function (): TransportResponse {
            [$headers, $body] = $this->platformResponse('{"code":"00000"}');
            return new TransportResponse(200, $headers, $body);
        });
        $client = $this->clientWithTransport($transport);
        $result = $client->execute('POST', self::PATH, '{"code":"00000"}', 'L0');
        $this->assertTrue($result->ok);
        $this->assertSame('{"code":"00000"}', $result->plaintext);
    }

    public function testResetDefaultReloadsConfig(): void
    {
        $firstPath = sys_get_temp_dir() . '/wop-reset-a-' . bin2hex(random_bytes(3)) . '.json';
        $secondPath = sys_get_temp_dir() . '/wop-reset-b-' . bin2hex(random_bytes(3)) . '.json';
        file_put_contents($firstPath, $this->configJson('app_first'));
        file_put_contents($secondPath, $this->configJson('app_second'));

        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV . '=' . $firstPath);
        $first = WopClient::defaultClient();
        WopConfigLoader::clearCache();
        WopClient::resetDefault();
        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV . '=' . $secondPath);
        $second = WopClient::defaultClient();

        $this->assertNotSame($first, $second);
        @unlink($firstPath);
        @unlink($secondPath);
        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV);
    }

    private function clientWithTransport(TransportInterface $transport): WopClient
    {
        $keys = self::keys()['rsa3072'];
        return WopClient::fromConfig(WopSdkConfig::builder()
            ->appKey('app_10012481831')
            ->suite('WOP-RSA3072-SHA256')
            ->merchantPrivateKey($keys['privatePkcs8B64'])
            ->platformPublicKey($keys['publicSpkiB64'])
            ->serverRoot('https://gw.example.com/gateway')
            ->transport($transport)
            ->build());
    }

    /** @return array{0: array<string, string>, 1: string} */
    private function platformResponse(string $plainBody): array
    {
        $headers = [];
        $wireBody = $plainBody;
        $headers['x-wop-nonce'] = 'respnonce00000000000000000000a';
        $headers['x-wop-timestamp'] = '1774340000000';
        if ($wireBody !== '') {
            $headers['x-wop-content-digest'] = \Wop\Sdk\ContentDigest::build(
                $wireBody,
                \Wop\Sdk\Suite::parse('WOP-RSA3072-SHA256')
            );
        }
        $signedNames = ['x-wop-nonce', 'x-wop-timestamp'];
        if (isset($headers['x-wop-content-digest'])) {
            $signedNames[] = 'x-wop-content-digest';
        }
        sort($signedNames, SORT_STRING);
        $canonical = \Wop\Sdk\CanonicalRequest::build(
            'v1/1800',
            'POST',
            self::PATH,
            '',
            \Wop\Sdk\CanonicalRequest::canonicalHeaders(array_intersect_key(
                $headers,
                array_flip($signedNames)
            ))
        );
        $signature = \Wop\Sdk\RsaSigner::sign($canonical, self::keys()['rsa3072']['privatePkcs8B64']);
        $headers['x-wop-sign'] = \Wop\Sdk\SignHeader::build(
            'WOP-RSA3072-SHA256',
            1800,
            $signedNames,
            $signature
        );
        return [$headers, $wireBody];
    }

    private function configJson(string $appKey): string
    {
        $keys = self::keys()['rsa3072'];
        return json_encode([
            'appKey' => $appKey,
            'suite' => 'WOP-RSA3072-SHA256',
            'merchantPrivateKey' => $keys['privatePkcs8B64'],
            'platformPublicKey' => $keys['publicSpkiB64'],
            'serverRoot' => 'https://gw.example.com/gateway',
            'backupServerRoots' => [],
            'expiredSeconds' => 1800,
            'httpClient' => [
                'connectTimeout' => 10000,
                'readTimeout' => 30000,
                'maxRetryCount' => 3,
            ],
        ], JSON_UNESCAPED_UNICODE);
    }
}

/** 测试用传输桩：按 callable 返回预设响应。 */
final class StubTransport implements TransportInterface
{
    /** @param callable(): TransportResponse $responder */
    public function __construct(private readonly \Closure $responder)
    {
    }

    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        unset($method, $url, $headers, $body);
        return ($this->responder)();
    }
}
