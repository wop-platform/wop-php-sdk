<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * 黄金向量加载基类：CI 与本地消费同一副本（tests/fixtures/crypto-vectors.json，禁改）。
 */
abstract class VectorCase extends TestCase
{
    /** @var array<string, mixed>|null */
    private static ?array $vectors = null;

    /**
     * @return array<string, mixed>
     */
    protected static function vectors(): array
    {
        if (self::$vectors === null) {
            $path = __DIR__ . '/fixtures/crypto-vectors.json';
            $decoded = json_decode((string) file_get_contents($path), true);
            if (!is_array($decoded)) {
                throw new RuntimeException('fixture 解析失败: ' . $path);
            }
            self::$vectors = $decoded;
        }
        return self::$vectors;
    }

    /**
     * @return array<string, mixed>
     */
    protected static function inputs(): array
    {
        return self::vectors()['inputs'];
    }

    /**
     * @return array<string, mixed>
     */
    protected static function keys(): array
    {
        return self::vectors()['keys'];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    protected static function vectorList(string $section): array
    {
        $list = self::vectors()[$section] ?? [];
        assert(is_array($list));
        return $list;
    }

    protected static function vector(string $section, string $id): array
    {
        foreach (self::vectorList($section) as $item) {
            if ($item['id'] === $id) {
                return $item;
            }
        }
        throw new RuntimeException("向量不存在: $section/$id");
    }

    protected static function b64uDecode(string $s): string
    {
        $decoded = base64_decode(strtr($s, '-_', '+/'), true);
        if ($decoded === false) {
            throw new RuntimeException('非法 base64url: ' . $s);
        }
        return $decoded;
    }
}
