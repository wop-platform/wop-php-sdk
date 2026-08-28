<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\Transport\CurlTransport;
use Wop\Sdk\Transport\GuzzleTransport;
use Wop\Sdk\Transport\TransportInterface;

/**
 * spec:Q1 — HTTP 适配层：curl 扩展适配器 + Guzzle peer 适配器。
 * 对 php -S 内置 echo 服务做真实 roundtrip。
 */
final class TransportTest extends TestCase
{
    private static string $baseUrl;
    private static ?object $serverProc = null;

    public static function setUpBeforeClass(): void
    {
        $router = sys_get_temp_dir() . '/wop-sdk-echo-router.php';
        file_put_contents($router, <<<'PHP'
<?php
$in = [
    'method' => $_SERVER['REQUEST_METHOD'],
    'path' => $_SERVER['REQUEST_URI'],
    'body' => file_get_contents('php://input'),
    'x_wop_sign' => $_SERVER['HTTP_X_WOP_SIGN'] ?? null,
];
header('Content-Type: application/json');
header('X-Echo-Server: wop-test');
echo json_encode($in, JSON_UNESCAPED_UNICODE);
PHP
        );
        $port = random_int(18000, 25000);
        self::$baseUrl = "127.0.0.1:{$port}";
        $cmd = sprintf('exec %s -S %s %s >/dev/null 2>&1', PHP_BINARY, self::$baseUrl, escapeshellarg($router));
        $procHandle = proc_open($cmd, [1 => ['file', '/dev/null', 'w']], $pipes);
        self::$serverProc = (object) ['handle' => $procHandle];
        usleep(150000); // 等待 listen
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverProc !== null) {
            proc_terminate(self::$serverProc->handle);
            proc_close(self::$serverProc->handle);
            self::$serverProc = null;
        }
    }

    public function testCurlTransportRoundtrip(): void
    {
        $transport = new CurlTransport();
        $this->exerciseRoundtrip($transport);
    }

    public function testGuzzleTransportRoundtrip(): void
    {
        $transport = new GuzzleTransport();
        $this->exerciseRoundtrip($transport);
    }

    public function testCurlTransportExposesCurlError(): void
    {
        $transport = new CurlTransport();
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('传输失败');
        $transport->send('GET', 'http://127.0.0.1:1/nope', [], '');
    }

    public function testGuzzleTransportExposesGuzzleError(): void
    {
        $transport = new GuzzleTransport();
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('传输失败');
        $transport->send('GET', 'http://127.0.0.1:1/nope', [], '');
    }

    public function testResponseHeaderLookupIsCaseInsensitive(): void
    {
        $response = new \Wop\Sdk\Transport\TransportResponse(200, ['Content-Type' => 'application/json'], '{}');
        $this->assertSame('application/json', $response->header('content-type'));
        $this->assertSame('application/json', $response->header('CONTENT-TYPE'));
        $this->assertNull($response->header('missing'));
        $this->assertTrue($response->isSuccess());
        $this->assertFalse((new \Wop\Sdk\Transport\TransportResponse(500, [], ''))->isSuccess());
    }

    private function exerciseRoundtrip(TransportInterface $transport): void
    {
        $sign = 'WOP-RSA3072-SHA256 v1/1800/x-wop-appkey/sig-nonce';
        $body = '{"biz":"query","note":"中文"}';
        $response = $transport->send(
            'POST',
            'http://' . self::$baseUrl . '/gateway/echo?x=1',
            ['Content-Type: application/json', 'x-wop-sign: ' . $sign],
            $body
        );

        $this->assertTrue($response->isSuccess(), get_class($transport) . ' 状态码: ' . $response->statusCode);
        $this->assertSame('wop-test', $response->header('x-echo-server'));
        $decoded = json_decode($response->body, true);
        $this->assertSame('POST', $decoded['method']);
        $this->assertSame('/gateway/echo?x=1', $decoded['path']);
        $this->assertSame($body, $decoded['body'], 'wire body 字节原样送达');
        $this->assertSame($sign, $decoded['x_wop_sign'], 'x-wop-sign 头原样送达');
    }


    public function testGuzzleTransportSkipsMalformedHeaderLines(): void
    {
        $transport = new GuzzleTransport();
        $response = $transport->send('GET', 'http://' . self::$baseUrl . '/x', ['ok: 1', 'malformed-line'], '');
        $this->assertTrue($response->isSuccess());
    }
}
