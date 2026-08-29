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

    /**
     * formatRules 全量契约入口（三件套之"未知类别哨兵"）：
     * 出现未归类 id（既非 header- 也非 b64url-）时抛出——真源新增类别时防静默漏消费。
     * 静态方法：DataProvider 直接调用（provider 无实例上下文）。
     *
     * @return list<array<string, mixed>>
     */
    public static function formatRulesAll(): array
    {
        $decoded = json_decode((string) file_get_contents(__DIR__ . '/fixtures/crypto-vectors.json'), true);
        if (!is_array($decoded)) {
            throw new RuntimeException('fixture 解析失败');
        }
        $rules = $decoded['formatRules'] ?? [];
        foreach ($rules as $rule) {
            $id = (string) $rule['id'];
            if (!\str_starts_with($id, 'header-') && !\str_starts_with($id, 'b64url-')) {
                throw new RuntimeException('未知 formatRules 类别，须同步消费: ' . $id);
            }
        }
        return $rules;
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
