<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Wop\Sdk\WopException;

/**
 * Guzzle peer 适配器（guzzlehttp/guzzle 为 suggest 依赖，不污染核心依赖面）。
 */
final class GuzzleTransport implements TransportInterface
{
    /** 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读；与 .NET/Go/curl 对齐）。 */
    public const MAX_RESPONSE_BYTES = 11 << 20;

    private const READ_CHUNK = 65536;

    private readonly Client $client;
    /** 注入自定义 Client；缺省 30s 超时、http_errors=false（状态码自判）。 */
    public function __construct(?Client $client = null)
    {
        // guzzlehttp/guzzle 为 suggest/peer 依赖，缺失时 autoload 自然报错（README 注明）
        $this->client = $client ?? new Client(['http_errors' => false, 'timeout' => 30]);
    }

    /** 执行传输（实现 TransportInterface）；传输失败/响应体超限抛 WopException。 */
    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        try {
            $response = $this->client->request(\strtoupper($method), $url, [
                'headers' => self::toAssoc($headers),
                'body' => $body,
                'stream' => true, // 流式响应体：限额在读取过程中生效
            ]);
        } catch (GuzzleException $e) {
            throw new WopException('传输失败: ' . $e->getMessage(), 0, $e);
        }

        $responseHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $responseHeaders[$name] = \implode(', ', $values);
        }
        return new TransportResponse($response->getStatusCode(), $responseHeaders, self::readBodyLimited($response->getBody()));
    }

    /** 流式读取并累计字节；超限立即中止（防失控读）。 */
    private static function readBodyLimited(\Psr\Http\Message\StreamInterface $stream): string
    {
        $chunks = [];
        $received = 0;
        while (!$stream->eof()) {
            $chunk = $stream->read(self::READ_CHUNK);
            $received += \strlen($chunk);
            if ($received > self::MAX_RESPONSE_BYTES) {
                throw new WopException('响应体超过 ' . self::MAX_RESPONSE_BYTES . ' 字节上限');
            }
            $chunks[] = $chunk;
        }
        return \implode('', $chunks);
    }

    /**
     * @param list<string> $headerLines
     * @return array<string, string>
     */
    private static function toAssoc(array $headerLines): array
    {
        $assoc = [];
        foreach ($headerLines as $line) {
            $pos = \strpos($line, ':');
            if ($pos !== false) {
                $assoc[\trim(\substr($line, 0, $pos))] = \trim(\substr($line, $pos + 1));
            }
        }
        return $assoc;
    }
}
