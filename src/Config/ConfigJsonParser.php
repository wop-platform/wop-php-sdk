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

    private function __construct(private readonly string $json)
    {
    }

    public static function parse(string $json): WopSdkConfig
    {
        $trimmed = self::stripBom(trim($json));
        if ($trimmed === '') {
            throw WopException::configuration('配置文件 JSON 解析失败: 空文件');
        }
        return (new self($trimmed))->parseRoot();
    }

    private static function stripBom(string $text): string
    {
        return str_starts_with($text, "\u{FEFF}") ? substr($text, 3) : $text;
    }

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

    private function readInt(string $fieldName): int
    {
        $value = $this->readLong($fieldName);
        if ($value > PHP_INT_MAX) {
            throw WopException::configuration('配置字段 ' . $fieldName . ' 类型非法: 数值越界');
        }
        return $value;
    }

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

    private function skipArray(): void
    {
        $this->expect('[');
        while (!$this->tryConsume(']')) {
            $this->skipValue();
            $this->optionalComma();
        }
    }

    private function skipLiteral(): void
    {
        while ($this->pos < strlen($this->json) && ctype_alpha($this->json[$this->pos])) {
            $this->pos++;
        }
    }

    private function expect(string $ch): void
    {
        $this->skipWhitespace();
        if ($this->pos >= strlen($this->json) || $this->json[$this->pos] !== $ch) {
            throw $this->syntax("期望 '" . $ch . "'");
        }
        $this->pos++;
    }

    private function tryConsume(string $ch): bool
    {
        $this->skipWhitespace();
        if ($this->pos < strlen($this->json) && $this->json[$this->pos] === $ch) {
            $this->pos++;
            return true;
        }
        return false;
    }

    private function optionalComma(): void
    {
        $this->skipWhitespace();
        if ($this->pos < strlen($this->json) && $this->json[$this->pos] === ',') {
            $this->pos++;
        }
    }

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

    private function syntax(string $detail): WopException
    {
        return WopException::configuration('配置文件 JSON 解析失败: ' . $detail);
    }
}
