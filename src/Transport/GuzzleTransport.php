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
    private readonly Client $client;
    public function __construct(?Client $client = null)
    {
        // guzzlehttp/guzzle 为 suggest/peer 依赖，缺失时 autoload 自然报错（README 注明）
        $this->client = $client ?? new Client(['http_errors' => false, 'timeout' => 30]);
    }

    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        try {
            $response = $this->client->request(\strtoupper($method), $url, [
                'headers' => self::toAssoc($headers),
                'body' => $body,
            ]);
        } catch (GuzzleException $e) {
            throw new WopException('传输失败: ' . $e->getMessage(), 0, $e);
        }

        $responseHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $responseHeaders[$name] = \implode(', ', $values);
        }
        return new TransportResponse($response->getStatusCode(), $responseHeaders, (string) $response->getBody());
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
