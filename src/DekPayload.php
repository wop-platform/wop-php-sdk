<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * spec:F5/§6 — DEK 载荷：`alg$base64url(key)$base64url(iv)`。
 * `$` 不在 Base64URL 字母表中，分隔符无碰撞。
 */
final class DekPayload
{
    public const ALG_AES_256_GCM = 'AES-256-GCM';
    public const ALG_SM4_GCM = 'SM4-GCM';

    /** @var array<string, string> securityReq → 期望 alg（§6.2 映射） */
    private const ALG_BY_SUITE = [
        Suite::RSA3072 => self::ALG_AES_256_GCM,
        Suite::RSA4096 => self::ALG_AES_256_GCM,
        'WOP-SM2-SM3' => self::ALG_SM4_GCM,
    ];

    public function __construct(
        public readonly string $alg,
        public readonly string $key,
        public readonly string $iv,
    ) {
    }

    public function encode(): string
    {
        return $this->alg . '$' . Base64Url::encode($this->key) . '$' . Base64Url::encode($this->iv);
    }

    /**
     * §6.2/D8：alg 段与套件族一致性（RSA→AES-256-GCM，SM2→SM4-GCM）。
     */
    public function algMatches(string $securityReq): bool
    {
        return ($this::ALG_BY_SUITE[$securityReq] ?? null) === $this->alg;
    }

    /**
     * @throws WopException 空段/段数/非法 base64url
     */
    public static function decode(string $payloadText): self
    {
        $parts = \explode('$', $payloadText);
        if (\count($parts) !== 3) {
            throw new WopException('DEK 载荷格式错误（应为 alg$key$iv）');
        }
        [$alg, $keyB64u, $ivB64u] = $parts;
        if ($alg === '' || $keyB64u === '' || $ivB64u === '') {
            throw new WopException('DEK 载荷格式错误（存在空段）');
        }
        return new self($alg, Base64Url::decode($keyB64u), Base64Url::decode($ivB64u));
    }
}
