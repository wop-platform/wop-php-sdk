<?php

declare(strict_types=1);

namespace Wop\Sdk;

use phpseclib3\Crypt\RSA;

/**
 * spec:F5/D10/F2 — RSA-OAEP 显式双 SHA-256 + 空 label（DEK 包装）。
 * phpseclib OAEP 支持自定义 MGF1；openssl 扩展 OAEP 哈希写死与 MGF1 不匹配，不可用（B.1 注记）。
 *
 * wrap 自实现 EME-OAEP-ENCODE（RFC 8017：sha256 + MGF1-sha256 + 空 label），
 * RSAEP 走 phpseclib 无填充模式——seed 可注入，L2 构建字节级可复现
 * （interop 随机流合同：[nonce 池][CEK][IV][OAEP seed 32B] 按序消费）。
 * 解包失败对外一律模糊（I7）。
 */
final class RsaOaep
{
    private const HASH = 'sha256';
    private const HASH_LEN = 32;

    /** @var array<string, RSA\PrivateKey> */
    private static array $privateCache = [];

    /** @var array<string, RSA\PublicKey> 无填充公钥缓存（确定性 wrap 用） */
    private static array $rawPublicCache = [];

    /** 工具类禁实例化。 */
    private function __construct()
    {
    }

    /**
     * 公钥包装，返回 base64url 无填充。
     *
     * @param string|null $seed 显式 OAEP seed（32 字节，测试/联调复现用）；
     *                          缺省 CSPRNG 生成——生产路径行为与注入无关
     */
    public static function wrap(string $plaintext, string $publicKey, ?string $seed = null): string
    {
        $key = self::rawPublicKey($publicKey);
        $k = \intdiv($key->getLength() + 7, 8);
        $em = self::oaepEncode($plaintext, $seed ?? \random_bytes(self::HASH_LEN), $k);
        return Base64Url::encode($key->encrypt($em));
    }

    /**
     * 私钥解包；失败（含 mgf1-sha1 陷阱密文、篡改）返回 null——失败细节对外模糊（I7）。
     */
    public static function unwrap(string $cipherB64u, string $privateKey): ?string
    {
        try {
            $cipher = Base64Url::decode($cipherB64u);
            return self::privateKey($privateKey)->decrypt($cipher);
        } catch (\Throwable) {
            return null;
        }
    }

    /** EME-OAEP-ENCODE（RFC 8017 §7.1.1）：EM = 0x00 ‖ maskedSeed ‖ maskedDB。 */
    private static function oaepEncode(string $m, string $seed, int $k): string
    {
        if (\strlen($seed) !== self::HASH_LEN) {
            throw new WopException('OAEP seed 须为 ' . self::HASH_LEN . ' 字节');
        }
        $mLen = \strlen($m);
        if ($mLen > $k - 2 * self::HASH_LEN - 2) {
            throw new WopException('RSA-OAEP 明文超长');
        }
        $lHash = \hash(self::HASH, '', true);
        $ps = \str_repeat("\0", $k - $mLen - 2 * self::HASH_LEN - 2);
        $db = $lHash . $ps . "\x01" . $m;
        $maskedDb = $db ^ self::mgf1($seed, $k - self::HASH_LEN - 1);
        $maskedSeed = $seed ^ self::mgf1($maskedDb, self::HASH_LEN);
        return "\x00" . $maskedSeed . $maskedDb;
    }

    /** MGF1（RFC 8017 B.2.1，sha256）。 */
    private static function mgf1(string $seed, int $length): string
    {
        $t = '';
        for ($counter = 0; \strlen($t) < $length; $counter++) {
            $t .= \hash(self::HASH, $seed . \pack('N', $counter), true);
        }
        return \substr($t, 0, $length);
    }

    /** 私钥解析（OAEP 双 SHA-256 + 进程内缓存）；失败包 WopException。 */
    private static function privateKey(string $material): RSA\PrivateKey
    {
        $cached = self::$privateCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash(self::HASH)
                ->withMGFHash(self::HASH); // F2 钉子：MGF1 显式 SHA-256（JCA 默认是 SHA-1）
        } catch (\Throwable $e) {
            throw new WopException('RSA 私钥解析失败: ' . $e->getMessage(), 0, $e);
        }
        return self::$privateCache[$material] = $key;
    }

    /** 公钥解析为无填充模式（确定性 wrap 用）+ 缓存；失败包 WopException。 */
    private static function rawPublicKey(string $material): RSA\PublicKey
    {
        $cached = self::$rawPublicCache[$material] ?? null;
        if ($cached !== null) {
            return $cached;
        }
        try {
            $key = RSA::load($material)->withPadding(RSA::ENCRYPTION_NONE);
        } catch (\Throwable $e) {
            throw new WopException('RSA 公钥解析失败: ' . $e->getMessage(), 0, $e);
        }
        return self::$rawPublicCache[$material] = $key;
    }
}
