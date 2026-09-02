<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use RuntimeException;
use Wop\Sdk\Base64Url;
use Wop\Sdk\WopClient;
use Wop\Sdk\WopConfig;
use Wop\Sdk\WopException;

/**
 * spec:interop/v1 协议编排跨仓一致性合同消费端。
 *
 * fixture 为 wop-specs/interop/v1/interop-cases.json 的字节副本（禁手改，测试内
 * sha256 对真源钉死）。build 方向断言"同输入复现同 draft"（RSA 字节级；SM2 按
 * opaque 字段豁免密钥参与段——本仓 SM2 未支持，见 testSm2SuitesExplicitlyRejected）；
 * verify 方向断言跨仓编排与错误分类合同（本仓 reason → canonical class 映射见 classOf）。
 */
final class InteropConformanceTest extends VectorCase
{
    private const FIXTURE_PATH = __DIR__ . '/fixtures/interop-cases.json';

    /** 真源 sha256（wop-specs/interop/v1/interop-cases.json，格式 wop-interop-1，30 条）。 */
    private const FIXTURE_SHA256 = 'c920ca1a93ccb3899a659f59fed6ec4652cf9e1b3b58bbdac23c45ac3ed2353e';

    private const APP_KEY = 'app_interop_001';
    private const SM2_SUITE = 'WOP-SM2-SM3';

    /** @var array<string, mixed>|null */
    private static ?array $fixture = null;

    /** 已知用例 id 哨兵（真源漂移/新增未登记用例时防静默漏消费）。 */
    private const KNOWN_BUILD_IDS = [
        'build:WOP-RSA3072-SHA256:L0', 'build:WOP-RSA3072-SHA256:L2',
        'build:WOP-RSA4096-SHA256:L0', 'build:WOP-RSA4096-SHA256:L2',
        'build:WOP-SM2-SM3:L0', 'build:WOP-SM2-SM3:L2',
    ];
    private const KNOWN_POSITIVE_IDS = ['p07', 'p08', 'p09', 'p10', 'p11', 'p12', 'p13'];
    private const KNOWN_NEGATIVE_IDS = [
        'n01-encrypted-char-damage', 'n02-wire-tampered-after-signing',
        'n03-digest-tag-cross-family', 'n04-dek-alg-cross-family',
        'n05-dek-c1c2c3-order', 'n06-signature-b64-padding',
        'n07-signature-63b', 'n08-signature-65b',
        'n09-digest-missing', 'n10-digest-not-signed',
        'n11-suite-mismatch', 'n12-envelope-missing-field',
        'n13-dek-key-length', 'n14-missing-signed-header',
        'n15-digest-without-body', 'n17-encrypt-missing-dek',
        'n16-replay-cross-path',
    ];

    /**
     * 本仓错误标识（WopClient reason 常量）→ 跨仓 canonical class 显式映射表
     * （wop-specs/interop/v1 README「错误分类合同」）。四个 I7 模糊/明确类文案
     * 逐字对应；其余失败路径全部源自解析/结构/一致性类 WopException → protocol。
     */
    private static function classOf(?string $reason): string
    {
        return match ($reason) {
            WopClient::REASON_SIGN_FAIL => 'verify-failed',
            WopClient::REASON_DECRYPT_FAIL => 'decrypt-failed',
            WopClient::REASON_DIGEST_MISMATCH => 'digest-mismatch',
            WopClient::REASON_DEK_ALG_MISMATCH => 'alg-mismatch',
            default => 'protocol',
        };
    }

    // ==================== 哨兵与真源一致性 ====================

    /** spec:interop/消费要求1 — fixture 字节副本 sha256 与真源一致（防手改/漂移）。 */
    public function testFixtureMatchesSourceOfTruth(): void
    {
        $raw = (string) file_get_contents(self::FIXTURE_PATH);
        $this->assertSame(self::FIXTURE_SHA256, hash('sha256', $raw), 'fixture 与 wop-specs/interop/v1 真源失配');
    }

    /** spec:interop/消费要求4 — 条数哨兵 + 已知 id 哨兵 + 格式哨兵。 */
    public function testFixtureIntegritySentinels(): void
    {
        $f = self::fixture();
        $this->assertSame('wop-interop-1', $f['_meta']['format'], '样本集格式哨兵');
        $cases = $f['cases'];
        $this->assertCount(30, $cases, '总条数哨兵：30');
        $this->assertSame(30, $f['_meta']['caseCount'], 'caseCount 元数据哨兵');

        [$builds, $positives, $negatives] = [[], [], []];
        foreach ($cases as $case) {
            match ($case['kind']) {
                'build' => $builds[] = $case['id'],
                'verify-positive' => $positives[] = $case['id'],
                'verify-negative' => $negatives[] = $case['id'],
                default => throw new RuntimeException('未知 kind，须同步消费: ' . $case['kind']),
            };
        }
        $this->assertSame(self::KNOWN_BUILD_IDS, $builds, 'build 条数/已知 id 哨兵（6 条）');
        $this->assertSame(self::KNOWN_POSITIVE_IDS, $positives, 'positive 条数/已知 id 哨兵（7 条）');
        $this->assertSame(self::KNOWN_NEGATIVE_IDS, $negatives, 'negative 条数/已知 id 哨兵（17 条）');
    }

    // ==================== build 方向 ====================

    /**
     * spec:interop/build 合同 — 同 input（固定 timestamp/nonce/randomHex）复现同 draft。
     * RSA 族 reproduceMode=byte-exact：wire body 与全部头字节级一致（含 OAEP-from-stream
     * 的 dek 密文）。SM2 族 2 条由 testSm2SuitesExplicitlyRejected 显式拒绝（本仓未支持）。
     */
    public function testBuildConformanceByteExact(): void
    {
        $consumed = 0;
        foreach (self::fixture()['cases'] as $case) {
            if ($case['kind'] !== 'build') {
                continue;
            }
            if ($case['suite'] === self::SM2_SUITE) {
                continue; // 见 testSm2SuitesExplicitlyRejected
            }
            $input = $case['input'];
            $expected = $case['expected'];
            $this->assertSame('byte-exact', $expected['reproduceMode']);

            $stream = new HexStream($input['randomHex']);
            $draft = self::client($case['suite'])->buildRequest(
                $input['method'],
                $input['path'],
                self::b64uDecode($input['plaintextB64']),
                $case['level'],
                $input['timestampMs'],
                $input['nonce'],
                fn (int $length): string => $stream->take($length),
            );

            $this->assertSame(
                $expected['wireBodyB64'],
                Base64Url::encode($draft->wireBody),
                $case['id'] . ': wire body 字节不一致'
            );
            $opaque = $expected['opaque'] ?? [];
            foreach ($expected['headers'] as $name => $want) {
                $got = (string) $draft->header($name);
                if (in_array($name . '.signatureSegment', $opaque, true)) {
                    [$got, $want] = [self::stripSignatureSegment($got), self::stripSignatureSegment($want)];
                }
                if (in_array($name . '.dekValue', $opaque, true)) {
                    [$got, $want] = [self::stripDekValue($got), self::stripDekValue($want)];
                }
                $this->assertSame($want, $got, $case['id'] . ': 头 ' . $name . ' 不一致');
            }
            $this->assertCount(count($expected['headers']), $draft->headers, $case['id'] . ': 头集合不一致');
            $consumed++;
        }
        $this->assertSame(4, $consumed, 'build 消费条数哨兵：RSA 4 条（SM2 2 条显式拒绝）');
    }

    // ==================== verify 方向 ====================

    /** spec:interop/verify-positive — 正向通过且解密明文一致；头名大小写混合原样入（P7）。 */
    public function testVerifyPositiveConformance(): void
    {
        $consumed = 0;
        foreach (self::fixture()['cases'] as $case) {
            if ($case['kind'] !== 'verify-positive' || $case['suite'] === self::SM2_SUITE) {
                continue;
            }
            $result = self::client($case['suite'])->verifyResponse(
                $case['response']['headers'], // 混合大小写头名（P7）：SDK 自管头映射须大小写不敏感
                self::b64uDecode($case['response']['wireBodyB64']),
                $case['response']['path'],
                $case['response']['method'],
            );
            $this->assertTrue($result->ok, $case['id'] . ': 应通过（reason=' . $result->reason . '）');
            $this->assertSame(
                self::b64uDecode($case['expect']['plaintextB64']),
                $result->plaintext,
                $case['id'] . ': 明文不一致'
            );
            $consumed++;
        }
        $this->assertSame(5, $consumed, 'positive 消费条数哨兵：RSA 5 条（SM2 2 条显式拒绝）');
    }

    /** spec:interop/verify-negative — 必须拒绝且错误分类与 errorClass 逐条对账（含 P 系列静态等价样本）。 */
    public function testVerifyNegativeClassification(): void
    {
        $consumed = 0;
        foreach (self::fixture()['cases'] as $case) {
            if ($case['kind'] !== 'verify-negative' || $case['suite'] === self::SM2_SUITE) {
                continue;
            }
            $response = $case['response'];
            $verifyPath = $case['verifyPath'] ?? $response['path'];
            $result = self::client($case['suite'])->verifyResponse(
                $response['headers'],
                self::b64uDecode($response['wireBodyB64']),
                $verifyPath,
                $response['method'],
            );
            $this->assertFalse($result->ok, $case['id'] . ': 应拒绝');
            $this->assertSame(
                $case['expect']['errorClass'],
                self::classOf($result->reason),
                $case['id'] . ': 错误分类失配（reason=' . $result->reason . '）'
            );
            $consumed++;
        }
        $this->assertSame(13, $consumed, 'negative 消费条数哨兵：RSA 13 条（SM2 4 条显式拒绝）');
    }

    /**
     * spec:interop/SM2 — 样本集 8 条 SM2 用例（build 2 + positive 2 + negative 4）：
     * 本仓套件注册表明确拒绝 WOP-SM2-SM3（Q7 路线图，Suite::parse「暂未支持」），
     * 消费口径为"明确拒绝"而非静默跳过；SM2 支持落地后须改为全量消费。
     */
    public function testSm2SuitesExplicitlyRejected(): void
    {
        $sm2Ids = [];
        foreach (self::fixture()['cases'] as $case) {
            if ($case['suite'] !== self::SM2_SUITE) {
                continue;
            }
            $sm2Ids[] = $case['id'];
            try {
                self::client(self::SM2_SUITE);
                $this->fail($case['id'] . ': WOP-SM2-SM3 须被明确拒绝');
            } catch (WopException $e) {
                $this->assertStringContainsString('暂未支持', $e->getMessage(), $case['id'] . ': 支持类明确拒绝');
            }
        }
        $this->assertSame(8, count($sm2Ids), 'SM2 显式拒绝条数哨兵：8 条');
    }

    // ==================== helpers ====================

    /** @return array<string, mixed> */
    private static function fixture(): array
    {
        if (self::$fixture === null) {
            $decoded = json_decode((string) file_get_contents(self::FIXTURE_PATH), true);
            if (!is_array($decoded)) {
                throw new RuntimeException('interop fixture 解析失败: ' . self::FIXTURE_PATH);
            }
            self::$fixture = $decoded;
        }
        return self::$fixture;
    }

    /** 消费仓客户端：密钥材料与真源黄金向量同源（crypto-vectors.json 字节副本）。 */
    private static function client(string $suite): WopClient
    {
        $keySet = match ($suite) {
            'WOP-RSA4096-SHA256' => self::keys()['rsa4096'],
            'WOP-RSA3072-SHA256' => self::keys()['rsa3072'],
            default => self::keys()['sm2'], // 到达即由 Suite::parse 明确拒绝（暂未支持）
        };
        return new WopClient(new WopConfig(
            appKey: self::APP_KEY,
            securityReq: $suite,
            privateKey: $keySet['privatePkcs8B64'] ?? $keySet['privateDB64'],
            peerPublicKey: $keySet['publicSpkiB64'] ?? $keySet['publicPointB64'],
        ));
    }

    /** opaque 剥离：x-wop-sign 末段 '/' 之后的签名值（k 为 CSPRNG，合法变化）。 */
    private static function stripSignatureSegment(string $signHeader): string
    {
        $pos = strrpos($signHeader, '/');
        return $pos === false ? $signHeader : substr($signHeader, 0, $pos + 1);
    }

    /** opaque 剥离：x-wop-encrypt `dek=` 之后的包装密文（SM2 k 同理）。 */
    private static function stripDekValue(string $encryptHeader): string
    {
        $pos = strpos($encryptHeader, 'dek=');
        return $pos === false ? $encryptHeader : substr($encryptHeader, 0, $pos + 4);
    }
}

/**
 * interop 随机流消费（build 复现用确定性随机源）：按序取前段；耗尽填 0x5A
 * （与 Go 参考消费端 hexReader 语义一致——build 路径正常不会读至末尾）。
 */
final class HexStream
{
    private readonly string $bytes;
    private int $pos = 0;

    public function __construct(string $hex)
    {
        $decoded = @hex2bin($hex);
        if ($decoded === false) {
            throw new RuntimeException('interop randomHex 非法');
        }
        $this->bytes = $decoded;
    }

    public function take(int $length): string
    {
        $out = substr($this->bytes, $this->pos, $length);
        $this->pos += strlen($out);
        return str_pad($out, $length, "\x5A");
    }
}
