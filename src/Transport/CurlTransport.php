<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

use Wop\Sdk\WopException;

/**
 * curl 扩展适配器（默认交付；ext-curl 为 suggest 依赖）。
 */
final class CurlTransport implements TransportInterface
{
    public function __construct()
    {
        if (!function_exists('curl_init')) {
            throw new WopException('CurlTransport 需要 ext-curl（见 composer suggest）');
        }
    }

    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new WopException('传输失败: curl 初始化失败');
        }
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => 30,
        ]);
        $raw = curl_exec($handle);
        if ($raw === false) {
            throw new WopException('传输失败: ' . curl_error($handle));
        }
        $statusCode = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $headerSize = (int) curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        [$headerBlock, $responseBody] = [substr((string) $raw, 0, $headerSize), substr((string) $raw, $headerSize)];
        return new TransportResponse($statusCode, self::parseHeaders($headerBlock), $responseBody);
    }

    /** @return array<string, string> */
    private static function parseHeaders(string $headerBlock): array
    {
        $headers = [];
        foreach (preg_split('/\r?\n/', $headerBlock) ?: [] as $line) {
            $pos = strpos($line, ':');
            if ($pos !== false) {
                $headers[trim(substr($line, 0, $pos))] = trim(substr($line, $pos + 1));
            }
        }
        return $headers;
    }
}
