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
    /** @var string|null 本次类的唯一 router 路径（PID+随机后缀：并发套件互不共享，teardown 清理） */
    private static ?string $routerPath = null;

    public static function setUpBeforeClass(): void
    {
        // 11MB 限额组连续传输内存峰值超默认 128M（对齐覆盖率跑法 -d memory_limit=2G）
        if (ini_get('memory_limit') !== '-1') {
            ini_set('memory_limit', '1G');
        }
        $router = self::$routerPath = sys_get_temp_dir() . '/wop-sdk-echo-router-' . getmypid() . '-' . bin2hex(random_bytes(4)) . '.php';
        file_put_contents($router, <<<'PHP'
<?php
if (str_starts_with($_SERVER['REQUEST_URI'], '/huge')) {
    // 定长响应体端点：验证传输层响应体上限（流式计数中止）
    $n = (int) ($_GET['n'] ?? 0);
    header('Content-Type: application/octet-stream');
    echo str_repeat('a', $n);
    return;
}
if (str_starts_with($_SERVER['REQUEST_URI'], '/notfound')) {
    http_response_code(404);
    echo 'nope';
    return;
}
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
        // 端口竞争/慢启动重试：探测 TCP 真正 accept 后才继续（变异测试会连续数百次起停套件，
        // 固定 150ms sleep 会产生 flaky → 假 killed/survived）
        $port = null;
        $procHandle = false;
        for ($attempt = 0; $attempt < 10 && $port === null; $attempt++) {
            $candidate = random_int(18000, 25000);
            $cmd = sprintf('exec %s -S 127.0.0.1:%d %s >/dev/null 2>&1', PHP_BINARY, $candidate, escapeshellarg($router));
            $handle = proc_open($cmd, [1 => ['file', '/dev/null', 'w']], $pipes);
            for ($i = 0; $i < 40; $i++) {
                $sock = @fsockopen('127.0.0.1', $candidate, $errno, $errstr, 0.05);
                if ($sock !== false) {
                    fclose($sock);
                    $port = $candidate;
                    $procHandle = $handle;
                    break;
                }
                usleep(50000);
            }
            if ($port === null) {
                proc_terminate($handle);
                proc_close($handle);
            }
        }
        if ($port === null) {
            throw new \RuntimeException('测试内建服务器启动失败（10 次尝试）');
        }
        self::$baseUrl = "127.0.0.1:{$port}";
        self::$serverProc = (object) ['handle' => $procHandle];
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverProc !== null) {
            proc_terminate(self::$serverProc->handle);
            proc_close(self::$serverProc->handle);
            self::$serverProc = null;
        }
        if (self::$routerPath !== null) {
            @unlink(self::$routerPath);
            self::$routerPath = null;
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

    /** Q1 适配器语义：非 2xx 状态原样返回（http_errors=false），不得转为传输异常。 */
    #[\PHPUnit\Framework\Attributes\DataProvider('transportProvider')]
    public function testErrorStatusReturnedWithoutException(TransportInterface $transport): void
    {
        $response = $transport->send('GET', 'http://' . self::$baseUrl . '/notfound', [], '');
        $this->assertSame(404, $response->statusCode);
        $this->assertFalse($response->isSuccess());
    }

    /** @return list<list<TransportInterface>> */
    public static function transportProvider(): array
    {
        return [[new CurlTransport()], [new GuzzleTransport()]];
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


    // ==================== 响应体上限（11MB 级，流式计数中止） ====================

    public function testCurlTransportRejectsOversizedResponseBody(): void
    {
        $transport = new CurlTransport();
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('响应体超过');
        $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=' . (CurlTransport::MAX_RESPONSE_BYTES + 1), [], '');
    }

    public function testCurlTransportAcceptsExactLimitBody(): void
    {
        $transport = new CurlTransport();
        $response = $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=' . CurlTransport::MAX_RESPONSE_BYTES, [], '');
        $this->assertTrue($response->isSuccess());
        $this->assertSame(CurlTransport::MAX_RESPONSE_BYTES, strlen($response->body), '恰在上限的响应体须完整送达');
    }

    public function testGuzzleTransportRejectsOversizedResponseBody(): void
    {
        $transport = new GuzzleTransport();
        $this->expectException(\Wop\Sdk\WopException::class);
        $this->expectExceptionMessage('响应体超过');
        $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=' . (GuzzleTransport::MAX_RESPONSE_BYTES + 1), [], '');
    }

    public function testGuzzleTransportAcceptsExactLimitBody(): void
    {
        $transport = new GuzzleTransport();
        $response = $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=' . GuzzleTransport::MAX_RESPONSE_BYTES, [], '');
        $this->assertTrue($response->isSuccess());
        $this->assertSame(GuzzleTransport::MAX_RESPONSE_BYTES, strlen($response->body), '恰在上限的响应体须完整送达');
    }

    public function testGuzzleTransportSkipsMalformedHeaderLines(): void
    {
        $transport = new GuzzleTransport();
        $response = $transport->send('GET', 'http://' . self::$baseUrl . '/x', ['ok: 1', 'malformed-line'], '');
        $this->assertTrue($response->isSuccess());
    }

    /**
     * D4 限额硬编码锚：11<<20 = 11534336 字节恰过、+1 拒。
     * 刻意不引用 MAX_RESPONSE_BYTES 常量——常量漂移时本测试是独立哨兵。
     */
    public function testResponseLimitHardcodedBoundary(): void
    {
        foreach ([new CurlTransport(), new GuzzleTransport()] as $transport) {
            $ok = $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=11534336', [], '');
            $this->assertSame(11534336, strlen($ok->body), get_class($transport));
            try {
                $transport->send('GET', 'http://' . self::$baseUrl . '/huge?n=11534337', [], '');
                $this->fail(get_class($transport) . ' 11534337 字节应超限拒绝');
            } catch (\Wop\Sdk\WopException $e) {
                $this->assertStringContainsString('11534336 字节上限', $e->getMessage(), '限额消息含精确数值与单位');
            }
        }
    }

    /** isSuccess 状态码边界：2xx 恰含 199 排除、299/300 分界。 */
    public function testIsSuccessStatusBoundaries(): void
    {
        $this->assertFalse((new \Wop\Sdk\Transport\TransportResponse(199, [], ''))->isSuccess());
        $this->assertTrue((new \Wop\Sdk\Transport\TransportResponse(299, [], ''))->isSuccess());
        $this->assertFalse((new \Wop\Sdk\Transport\TransportResponse(300, [], ''))->isSuccess());
    }
}
