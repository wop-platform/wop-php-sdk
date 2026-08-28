<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F1 — securityReq 解析（单一注册表，D13：无运行时配置入口）。
 * 首版仅 RSA 套件（Q7）；SM2-SM3 明确抛"暂未支持"。
 */
final class Suite
{
    public const RSA3072 = 'WOP-RSA3072-SHA256';
    public const RSA4096 = 'WOP-RSA4096-SHA256';

    private const SM_SUITE = 'WOP-SM2-SM3';

    /** @var array<string, array{keyAlgorithm: string, keyLength: int, digestLabel: string, dekAlg: string}> */
    private const REGISTRY = [
        'WOP-RSA3072-SHA256' => ['keyAlgorithm' => 'RSA', 'keyLength' => 3072, 'digestLabel' => 'sha-256', 'dekAlg' => 'AES-256-GCM'],
        'WOP-RSA4096-SHA256' => ['keyAlgorithm' => 'RSA', 'keyLength' => 4096, 'digestLabel' => 'sha-256', 'dekAlg' => 'AES-256-GCM'],
    ];

    /** 国际/国密合法密钥与摘要算法标识（支持类判定用，spec §2.2）。 */
    private const KNOWN_KEY_ALGS = ['RSA3072', 'RSA4096', 'SM2'];
    private const KNOWN_DIGEST_ALGS = ['SHA256', 'SM3'];

    private function __construct(
        public readonly string $securityReq,
        public readonly string $keyAlgorithm,
        public readonly int $keyLength,
        public readonly string $digestLabel,
        public readonly string $dekAlg,
    ) {
    }

    /**
     * @throws WopException 解析类（格式）/支持类（算法/跨族/暂未支持）
     */
    public static function parse(string $securityReq): self
    {
        $trimmed = \trim($securityReq);
        if ($trimmed === '') {
            throw new WopException('securityReq 格式错误: 空值');
        }
        if ($trimmed === self::SM_SUITE) {
            throw new WopException('SM2-SM3 套件暂未支持，见 README 路线图');
        }
        $segments = \explode('-', $trimmed);
        if (\count($segments) !== 3 || $segments[0] !== 'WOP') {
            throw new WopException('securityReq 格式错误（应为 WOP-<密钥算法>-<摘要算法>）: ' . $trimmed);
        }
        [, $keyAlg, $digestAlg] = $segments;
        if (!\in_array($keyAlg, self::KNOWN_KEY_ALGS, true) || !\in_array($digestAlg, self::KNOWN_DIGEST_ALGS, true)) {
            throw new WopException('不支持的算法组合: ' . $trimmed);
        }
        // 到这里标识均在支持列表：剩下的组合只可能是跨族（国际密钥+国密摘要或反之）
        $entry = self::REGISTRY[$trimmed] ?? null;
        if ($entry === null) {
            throw new WopException('不支持的算法组合（国际/国密跨族禁止）: ' . $trimmed);
        }
        return new self(
            $trimmed,
            $entry['keyAlgorithm'],
            $entry['keyLength'],
            $entry['digestLabel'],
            $entry['dekAlg'],
        );
    }
}
