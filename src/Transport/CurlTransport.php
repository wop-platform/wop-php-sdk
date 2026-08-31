<?php

declare(strict_types=1);

namespace Wop\Sdk\Transport;

use Wop\Sdk\WopException;

/**
 * curl 扩展适配器（默认交付；ext-curl 为 suggest 依赖）。
 */
final class CurlTransport implements TransportInterface
{
    /** 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读；与 .NET/Go 对齐）。 */
    public const MAX_RESPONSE_BYTES = 11 << 20;

    private const READ_CHUNK = 65536;

    /** 空构造：句柄按请求创建，无跨请求可变状态。 */
    public function __construct()
    {
        // ext-curl 为 suggest 依赖（composer.json/README 注明），缺失时 curl_init 未定义会自然报错
    }

    /** 执行传输（实现 TransportInterface）；传输失败/响应体超限抛 WopException。 */
    public function send(string $method, string $url, array $headers, string $body): TransportResponse
    {
        $handle = curl_init($url);

        // 流式计数：write 回调累计响应体字节，超限立即中止下载（而非读完后检查）
        $rawHeader = '';
        $bodyChunks = [];
        $received = 0;
        $overflow = false;
        \curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => \strtoupper($method),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_BUFFERSIZE => self::READ_CHUNK,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$rawHeader): int {
                $rawHeader .= $line;
                return \strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$bodyChunks, &$received, &$overflow): int {
                $received += \strlen($chunk);
                if ($received > self::MAX_RESPONSE_BYTES) {
                    $overflow = true;
                    return -1; // 非长度返回值中止传输
                }
                $bodyChunks[] = $chunk;
                return \strlen($chunk);
            },
        ]);
        $raw = curl_exec($handle);
        $statusCode = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        // PHP 8.0+ 句柄随引用释放自动关闭（curl_close 已于 8.5 弃用）

        if ($overflow) {
            throw new WopException('响应体超过 ' . self::MAX_RESPONSE_BYTES . ' 字节上限');
        }
        if ($raw === false) {
            throw new WopException('传输失败: ' . $error);
        }

        return new TransportResponse($statusCode, self::parseHeaders($rawHeader), \implode('', $bodyChunks));
    }

    /** @return array<string, string> */
    private static function parseHeaders(string $headerBlock): array
    {
        $headers = [];
        foreach (\preg_split('/\r?\n/', $headerBlock) ?: [] as $line) {
            $pos = \strpos($line, ':');
            if ($pos !== false) {
                $headers[\trim(\substr($line, 0, $pos))] = \trim(\substr($line, $pos + 1));
            }
        }
        return $headers;
    }
}
