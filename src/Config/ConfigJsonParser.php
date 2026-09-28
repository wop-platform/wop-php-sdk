<?php

declare(strict_types=1);

namespace Wop\Sdk\Config;

use Wop\Sdk\WopClient;
use Wop\Sdk\WopException;

/**
 * 配置专用极简 JSON 解析器（K8/K21）：忽略未知顶层字段；检测重复键；
 * 支持一层嵌套 httpClient 对象。
 */
final class ConfigJsonParser
{
    private int $pos = 0;

        /** 私有构造：经 parse() 进入（输入为剥 BOM 后的 JSON 串）。 */
    private function __construct(private readonly string $json)
    {
    }

        /** 极简 JSON 解析入口（K8/K21：重复键、类型不符、越界即 configuration，§4.4）。 */
    public static function parse(string $json): WopSdkConfig
    {
        $trimmed = self::stripBom(trim($json));
        if ($trimmed === '') {
            throw WopException::configuration('配置文件 JSON 解析失败: 空文件');
        }
        return (new self($trimmed))->parseRoot();
    }

        /** 剥离 UTF-8 BOM（§4.3 容忍并剥离）。 */
    private static function stripBom(string $text): string
    {
        return str_starts_with($text, "\u{FEFF}") ? substr($text, 3) : $text;
    }

        /** 根对象解析：仅一层嵌套（httpClient），未知字段忽略（§4.4）。 */
    private function parseRoot(): WopSdkConfig
    {
        $this->expect('{');
        $appKey = null;
        $suite = null;
        $merchantPrivateKey = null;
        $platformPublicKey = null;
        $serverRoot = null;
        /** @var list<string> */
        $backupServerRoots = [];
        $expiredSeconds = null;
        $httpClient = null;
        /** @var array<string, true> */
        $seen = [];
        while (!$this->tryConsume('}')) {
            $key = $this->readString();
            $this->requireDuplicateFree($seen, $key);
            $this->expect(':');
            switch ($key) {
                case 'appKey':
                    $appKey = $this->readString();
                    break;
                case 'suite':
                    $suite = $this->readString();
                    break;
                case 'merchantPrivateKey':
                    $merchantPrivateKey = $this->readString();
                    break;
                case 'platformPublicKey':
                    $platformPublicKey = $this->readString();
                    break;
                case 'serverRoot':
                    $serverRoot = $this->readString();
                    break;
                case 'backupServerRoots':
                    $backupServerRoots = $this->readStringArray();
                    break;
                case 'expiredSeconds':
                    $expiredSeconds = $this->readLong('expiredSeconds');
                    break;
                case 'httpClient':
                    $httpClient = $this->readHttpClient();
                    break;
                default:
                    $this->skipValue();
            }
            $this->optionalComma();
        }

        $expired = $expiredSeconds ?? WopClient::DEFAULT_EXPIRED_SECONDS;
        $raw = new WopSdkConfig(
            $appKey ?? '',
            $suite ?? '',
            $merchantPrivateKey ?? '',
            $platformPublicKey ?? '',
            $serverRoot ?? '',
            $backupServerRoots,
            $expired,
            $httpClient ?? HttpClientSettings::defaults(),
        );
        return ConfigValidator::validateAndNormalize($raw);
    }

        /** 解析 httpClient 对象（缺省 10000/30000/3，指针字段区分缺省与显式零值）。 */
    private function readHttpClient(): HttpClientSettings
    {
        $this->expect('{');
        $connect = null;
        $read = null;
        $maxRetry = null;
        /** @var array<string, true> */
        $seen = [];
        while (!$this->tryConsume('}')) {
            $key = $this->readString();
            $this->requireDuplicateFree($seen, $key);
            $this->expect(':');
            switch ($key) {
                case 'connectTimeout':
                    $connect = $this->readInt('httpClient.connectTimeout');
                    break;
                case 'readTimeout':
                    $read = $this->readInt('httpClient.readTimeout');
                    break;
                case 'maxRetryCount':
                    $maxRetry = $this->readInt('httpClient.maxRetryCount');
                    break;
                default:
                    $this->skipValue();
            }
            $this->optionalComma();
        }
        return new HttpClientSettings(
            $connect ?? HttpClientSettings::DEFAULT_CONNECT_TIMEOUT,
            $read ?? HttpClientSettings::DEFAULT_READ_TIMEOUT,
            $maxRetry ?? HttpClientSettings::DEFAULT_MAX_RETRY_COUNT,
        );
    }

    /** @return list<string> */
        /** 读取字符串数组字段（backupServerRoots；非字符串元素即 configuration）。 */
    private function readStringArray(): array
    {
        $this->expect('[');
        $values = [];
        while (!$this->tryConsume(']')) {
            $values[] = $this->readString();
            $this->optionalComma();
        }
        return $values;
    }

    /** @param array<string, true> $seen */
    private function requireDuplicateFree(array &$seen, string $key): void
    {
        if (isset($seen[$key])) {
            throw WopException::configuration('配置字段 ' . $key . ' 重复: ' . $key);
        }
        $seen[$key] = true;
    }

        /** 读取字符串字段（类型不符即 configuration，消息含字段名）。 */
    private function readString(): string
    {
        $this->skipWhitespace();
        if ($this->pos >= strlen($this->json) || $this->json[$this->pos] !== '"') {
            throw $this->syntax('期望字符串');
        }
        $this->pos++;
        $sb = '';
        while ($this->pos < strlen($this->json)) {
            $c = $this->json[$this->pos++];
            if ($c === '"') {
                return $sb;
            }
            if ($c === '\\') {
                if ($this->pos >= strlen($this->json)) {
                    throw $this->syntax('字符串转义不完整');
                }
                $esc = $this->json[$this->pos++];
                $sb .= match ($esc) {
                    '"', '\\', '/' => $esc,
                    'b' => "\x08",
                    'f' => "\x0C",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    'u' => $this->readUnicode(),
                    default => throw $this->syntax('非法转义 \\' . $esc),
                };
            } else {
                $sb .= $c;
            }
        }
        throw $this->syntax('字符串未闭合');
    }

        /** 读取字符串字面量（RFC 8259 完整转义集，含 \uXXXX 代理对）。 */
    private function readUnicode(): string
    {
        if ($this->pos + 4 > strlen($this->json)) {
            throw $this->syntax('\\u 转义不完整');
        }
        $hex = substr($this->json, $this->pos, 4);
        if (!ctype_xdigit($hex)) {
            throw $this->syntax('\\u 转义非法');
        }
        $this->pos += 4;
        return mb_chr((int) hexdec($hex), 'UTF-8');
    }

        /** 读取整数字段（long 域，越界即 configuration）。 */
    private function readLong(string $fieldName): int
    {
        $this->skipWhitespace();
        $start = $this->pos;
        if ($this->pos < strlen($this->json) && $this->json[$this->pos] === '-') {
            $this->pos++;
        }
        while ($this->pos < strlen($this->json) && ctype_digit($this->json[$this->pos])) {
            $this->pos++;
        }
        if ($start === $this->pos) {
            throw $this->syntax('期望数字');
        }
        $num = substr($this->json, $start, $this->pos - $start);
        if (!ctype_digit($num)) {
            throw WopException::configuration('配置字段 ' . $fieldName . ' 类型非法: ' . $num);
        }
        $value = (int) $num;
        if ($value <= 0) {
            throw WopException::configuration('配置字段 ' . $fieldName . ' 类型非法: ' . $num);
        }
        return $value;
    }

        /** 读取整数字段（int 域，越界即 configuration）。 */
    private function readInt(string $fieldName): int
    {
        $value = $this->readLong($fieldName);
        if ($value > PHP_INT_MAX) {
            throw WopException::configuration('配置字段 ' . $fieldName . ' 类型非法: 数值越界');
        }
        return $value;
    }

        /** 跳过未知字段的任意值（对象/数组/串/数/字面量）。 */
    private function skipValue(): void
    {
        $this->skipWhitespace();
        if ($this->pos >= strlen($this->json)) {
            throw $this->syntax('意外结束');
        }
        $c = $this->json[$this->pos];
        if ($c === '"') {
            $this->readString();
        } elseif ($c === '{') {
            $this->skipObject();
        } elseif ($c === '[') {
            $this->skipArray();
        } elseif ($c === 't' || $c === 'f' || $c === 'n') {
            $this->skipLiteral();
        } else {
            while ($this->pos < strlen($this->json) && !str_contains(',]}', $this->json[$this->pos])) {
                $this->pos++;
            }
        }
    }

        /** 跳过对象值（一层嵌套上限：根内对象再嵌对象即 configuration）。 */
    private function skipObject(): void
    {
        $this->expect('{');
        while (!$this->tryConsume('}')) {
            $this->readString();
            $this->expect(':');
            $this->skipValue();
            $this->optionalComma();
        }
    }

        /** 跳过数组值。 */
    private function skipArray(): void
    {
        $this->expect('[');
        while (!$this->tryConsume(']')) {
            $this->skipValue();
            $this->optionalComma();
        }
    }

        /** 跳过 true/false/null 字面量。 */
    private function skipLiteral(): void
    {
        while ($this->pos < strlen($this->json) && ctype_alpha($this->json[$this->pos])) {
            $this->pos++;
        }
    }

        /** 消费期望字节，不符即 syntax 异常。 */
    private function expect(string $ch): void
    {
        $this->skipWhitespace();
        if ($this->pos >= strlen($this->json) || $this->json[$this->pos] !== $ch) {
            throw $this->syntax("期望 '" . $ch . "'");
        }
        $this->pos++;
    }

        /** 尝试消费字节：命中返回 true。 */
    private function tryConsume(string $ch): bool
    {
        $this->skipWhitespace();
        if ($this->pos < strlen($this->json) && $this->json[$this->pos] === $ch) {
            $this->pos++;
            return true;
        }
        return false;
    }

        /** 读取可选逗号（对象/数组元素分隔）。 */
    private function optionalComma(): void
    {
        $this->skipWhitespace();
        if ($this->pos < strlen($this->json) && $this->json[$this->pos] === ',') {
            $this->pos++;
        }
    }

        /** 跳过空白（RFC 8259 四字符）。 */
    private function skipWhitespace(): void
    {
        while ($this->pos < strlen($this->json)) {
            $c = $this->json[$this->pos];
            if ($c === ' ' || $c === "\n" || $c === "\r" || $c === "\t") {
                $this->pos++;
            } else {
                break;
            }
        }
    }

        /** 构造统一语法异常（对外文案「配置文件 JSON 解析失败」）。 */
    private function syntax(string $detail): WopException
    {
        return WopException::configuration('配置文件 JSON 解析失败: ' . $detail);
    }
}
