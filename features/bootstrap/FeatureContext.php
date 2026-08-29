<?php

declare(strict_types=1);

use Behat\Behat\Context\Context;
use Wop\Sdk\Aes256Gcm;
use Wop\Sdk\Base64Url;
use Wop\Sdk\DekPayload;
use Wop\Sdk\EncryptedEnvelope;
use Wop\Sdk\EncryptHeader;
use Wop\Sdk\RequestDraft;
use Wop\Sdk\RsaOaep;
use Wop\Sdk\SignHeader;
use Wop\Sdk\Suite;
use Wop\Sdk\VerifyResult;
use Wop\Sdk\WopClient;
use Wop\Sdk\WopConfig;
use Wop\Sdk\WopException;

require_once __DIR__ . '/../../vendor/autoload.php';

/**
 * 商户使用场景步骤（docs/wop-sdk-scenario-matrix.md 矩阵的 Behat 轨）。
 *
 * 入向场景全部消费 interop 冻结样本（wop-specs/interop/v1 字节副本）——
 * spec D5：平台响应构造不得复用被测 SDK 出向代码。
 */
final class FeatureContext implements Context
{
    private const VECTORS_PATH = __DIR__ . '/../../tests/fixtures/crypto-vectors.json';
    private const INTEROP_PATH = __DIR__ . '/../../tests/fixtures/interop-cases.json';
    private const PATH = '/gateway/logistics.order.query';

    /** @var array<string, mixed>|null */
    private static ?array $vectors = null;

    /** @var array<string, mixed>|null */
    private static ?array $interop = null;

    private ?Suite $suite = null;
    private ?WopException $configError = null;

    /** @var array<string, mixed>|null 最近一次 buildRequest 参数（幂等场景复用） */
    private ?array $buildArgs = null;
    private ?RequestDraft $draft = null;
    private ?RequestDraft $draft2 = null;

    /** @var array<string, mixed>|null 入向当前 interop 样本 */
    private ?array $lastCase = null;
    private ?VerifyResult $lastResult = null;
    /** @var list<VerifyResult> 场景内累积的校验结果（I7 同文案断言用） */
    private array $results = [];

    // ==================== UC1 套件与配置 ====================

    /** @Given 商户选择套件 :req */
    public function selectSuite(string $req): void
    {
        $this->suite = null;
        $this->configError = null;
        try {
            $this->suite = Suite::parse(self::arg($req));
        } catch (WopException $e) {
            $this->configError = $e;
        }
    }

    /** @Then 客户端装配成功 */
    public function clientAssembles(): void
    {
        if ($this->suite === null) {
            throw new RuntimeException('套件装配失败: ' . ($this->configError?->getMessage() ?? '未知'));
        }
    }

    /** @Then 套件密钥长度为 :bits 位 */
    public function suiteKeyLengthIs(int $bits): void
    {
        $this->clientAssembles();
        if ($this->suite->keyLength !== $bits) {
            throw new RuntimeException("keyLength 期望 {$bits}，实际 {$this->suite->keyLength}");
        }
    }

    /** @Then 套件摘要标签为 :label */
    public function suiteDigestLabelIs(string $label): void
    {
        $this->clientAssembles();
        if ($this->suite->digestLabel !== self::arg($label)) {
            throw new RuntimeException("digestLabel 期望 {$label}，实际 {$this->suite->digestLabel}");
        }
    }

    /** @Then 套件 bulk 算法为 :alg */
    public function suiteDekAlgIs(string $alg): void
    {
        $this->clientAssembles();
        if ($this->suite->dekAlg !== self::arg($alg)) {
            throw new RuntimeException("dekAlg 期望 {$alg}，实际 {$this->suite->dekAlg}");
        }
    }

    /** @Then 客户端装配失败 */
    public function clientAssemblyFails(): void
    {
        if ($this->configError === null) {
            throw new RuntimeException('套件应被拒绝，实际装配成功: ' . $this->suite?->securityReq);
        }
    }

    /** @Then 错误文案包含 :fragment */
    public function errorContains(string $fragment): void
    {
        $fragment = self::arg($fragment);
        if ($this->configError === null || !str_contains($this->configError->getMessage(), $fragment)) {
            throw new RuntimeException('错误文案应包含「' . $fragment . '」，实际: ' . ($this->configError?->getMessage() ?? '无错误'));
        }
    }

    // ==================== UC2/UC3/UC4 出向请求构建 ====================

    /** @When 商户以固定时间戳 :ts 与 nonce :nonce 构建 :level :method 请求体 :body */
    public function buildWithBody(string $ts, string $nonce, string $level, string $method, string $body): void
    {
        $this->build((int) $ts, self::arg($nonce), self::arg($level), strtoupper(self::arg($method)), self::arg($body));
    }

    /** @When 商户以固定时间戳 :ts 与 nonce :nonce 构建 :level :method 请求无 body */
    public function buildWithoutBody(string $ts, string $nonce, string $level, string $method): void
    {
        $this->build((int) $ts, self::arg($nonce), self::arg($level), strtoupper(self::arg($method)), null);
    }

    /** @When 商户以相同参数再次构建 */
    public function buildAgain(): void
    {
        if ($this->buildArgs === null || $this->draft === null) {
            throw new RuntimeException('此前没有可复用的构建参数');
        }
        $this->draft2 = $this->merchantClient()->buildRequest(...$this->buildArgs);
    }

    /** @When 商户构建两个 GET 请求且不注入随机量 */
    public function buildTwoWithoutInjection(): void
    {
        $client = $this->merchantClient();
        $this->draft = $client->buildRequest('GET', '/p');
        $this->draft2 = $client->buildRequest('GET', '/p');
    }

    /** @Then 请求头 :name 值为 :value */
    public function headerEquals(string $name, string $value): void
    {
        $got = $this->draft()->header(self::arg($name));
        if ($got !== self::arg($value)) {
            throw new RuntimeException("头 {$name} 期望 {$value}，实际 " . var_export($got, true));
        }
    }

    /** @Then 请求携带 digest 头 */
    public function hasDigestHeader(): void
    {
        if ($this->draft()->header('x-wop-content-digest') === null) {
            throw new RuntimeException('应携带 x-wop-content-digest（D2/I1）');
        }
    }

    /** @Then 请求不携带 digest 头 */
    public function hasNoDigestHeader(): void
    {
        if ($this->draft()->header('x-wop-content-digest') !== null) {
            throw new RuntimeException('无 body 请求不应携带 digest（D2）');
        }
    }

    /** @Then digest 头已列入签名头的 signedHeaders */
    public function digestIsSigned(): void
    {
        $this->assertSignedHeaderListed('x-wop-content-digest');
    }

    /** @Then x-wop-encrypt 已列入签名头的 signedHeaders */
    public function encryptIsSigned(): void
    {
        $this->assertSignedHeaderListed('x-wop-encrypt');
    }

    /** @Then 线上体等于 :body */
    public function wireBodyEquals(string $body): void
    {
        if ($this->draft()->wireBody !== self::arg($body)) {
            throw new RuntimeException('线上体应为业务明文，实际: ' . $this->draft()->wireBody);
        }
    }

    /** @Then 线上体为空串 */
    public function wireBodyIsEmpty(): void
    {
        if ($this->draft()->wireBody !== '') {
            throw new RuntimeException('GET 无 body 线上体应为空串，实际: ' . $this->draft()->wireBody);
        }
    }

    /** @Then 请求头 :name 以 :prefix 开头 */
    public function headerStartsWith(string $name, string $prefix): void
    {
        $got = (string) $this->draft()->header(self::arg($name));
        if (!str_starts_with($got, self::arg($prefix))) {
            throw new RuntimeException("头 {$name} 应以 {$prefix} 开头，实际: " . $got);
        }
    }

    /** @Then 线上体为 L2 信封 JSON */
    public function wireBodyIsEnvelope(): void
    {
        try {
            EncryptedEnvelope::extract($this->draft()->wireBody);
        } catch (WopException $e) {
            throw new RuntimeException('线上体应为信封 JSON: ' . $e->getMessage());
        }
    }

    /** @Then 平台私钥可解开信封并还原明文 :plain */
    public function platformUnwraps(string $plain): void
    {
        $plain = self::arg($plain);
        $encrypt = EncryptHeader::parse($this->draft()->header('x-wop-encrypt'));
        $dek = DekPayload::decode((string) RsaOaep::unwrap((string) $encrypt->dek, self::keys()['rsa3072']['privatePkcs8B64']));
        $got = Aes256Gcm::decrypt(
            Base64Url::decode(EncryptedEnvelope::extract($this->draft()->wireBody)),
            $dek->iv,
            $dek->key,
        );
        if ($got !== $plain) {
            throw new RuntimeException('对端解开明文不一致: ' . var_export($got, true));
        }
    }

    /** @Then 两次构建的签名头完全一致 */
    public function bothSignHeadersEqual(): void
    {
        if ($this->draft()->header('x-wop-sign') !== $this->draft2()->header('x-wop-sign')) {
            throw new RuntimeException('同输入下签名头应幂等');
        }
    }

    /** @Then 两次构建的线上体完全一致 */
    public function bothWireBodiesEqual(): void
    {
        if ($this->draft()->wireBody !== $this->draft2()->wireBody) {
            throw new RuntimeException('同输入下线上体应幂等');
        }
    }

    /** @Then 两次构建的 nonce 互异 */
    public function noncesDiffer(): void
    {
        if ($this->draft()->header('x-wop-nonce') === $this->draft2()->header('x-wop-nonce')) {
            throw new RuntimeException('缺省 nonce 每次请求应重新生成（F9）');
        }
    }

    /** @Then 两次构建的 nonce 均为 32 位小写十六进制 */
    public function nonceFormat(): void
    {
        foreach ([$this->draft(), $this->draft2()] as $d) {
            if (!preg_match('/^[0-9a-f]{32}$/', (string) $d->header('x-wop-nonce'))) {
                throw new RuntimeException('nonce 应为 32 位小写 hex: ' . $d->header('x-wop-nonce'));
            }
        }
    }

    /** @Then 两次构建的时间戳均为 13 位毫秒 */
    public function timestampFormat(): void
    {
        foreach ([$this->draft(), $this->draft2()] as $d) {
            if (!preg_match('/^\d{13}$/', (string) $d->header('x-wop-timestamp'))) {
                throw new RuntimeException('timestamp 应为 13 位毫秒: ' . $d->header('x-wop-timestamp'));
            }
        }
    }

    // ==================== UC5/UC6 入向验证（interop 冻结样本，D5） ====================

    /** @When 商户收到 interop 样本 :id 的响应 */
    public function receiveInteropResponse(string $id): void
    {
        $case = self::interopCase(self::arg($id));
        $response = $case['response'];
        $this->lastCase = $case;
        $this->lastResult = $this->results[] = self::interopClient((string) $case['suite'])->verifyResponse(
            $response['headers'],
            self::b64uDecode((string) $response['wireBodyB64']),
            (string) ($case['verifyPath'] ?? $response['path']),
            (string) $response['method'],
        );
    }

    /** @When 商户通过回调地址 :url 验证 interop 样本 :id */
    public function verifyCallbackSample(string $url, string $id): void
    {
        $case = self::interopCase(self::arg($id));
        $response = $case['response'];
        $this->lastCase = $case;
        $this->lastResult = $this->results[] = self::interopClient((string) $case['suite'])->verifyCallback(
            $response['headers'],
            self::b64uDecode((string) $response['wireBodyB64']),
            self::arg($url),
        );
    }

    /** @Then 校验通过且明文还原 */
    public function verifyOkWithPlaintext(): void
    {
        $result = $this->lastResult ?? throw new RuntimeException('尚无校验结果');
        $case = $this->lastCase ?? throw new RuntimeException('尚无 interop 样本');
        if (!$result->ok) {
            throw new RuntimeException('应校验通过，实际失败: ' . $result->reason);
        }
        $expected = self::b64uDecode((string) $case['expect']['plaintextB64']);
        if ($result->plaintext !== $expected) {
            throw new RuntimeException('明文还原不一致');
        }
    }

    /** @Then 校验失败 */
    public function verifyFails(): void
    {
        $result = $this->lastResult ?? throw new RuntimeException('尚无校验结果');
        if ($result->ok) {
            throw new RuntimeException('应校验失败，实际通过');
        }
    }

    /** @Then 失败分类为 :class */
    public function failureClassIs(string $class): void
    {
        $result = $this->lastResult ?? throw new RuntimeException('尚无校验结果');
        $actual = self::classOf($result->reason);
        if ($actual !== self::arg($class)) {
            throw new RuntimeException("失败分类期望 {$class}，实际 {$actual}（reason={$result->reason}）");
        }
    }

    /** @Then 两次校验均失败 */
    public function bothVerificationsFail(): void
    {
        if (count($this->results) < 2) {
            throw new RuntimeException('场景内应已有两次校验');
        }
        foreach (array_slice($this->results, -2) as $result) {
            if ($result->ok) {
                throw new RuntimeException('两次校验均应失败');
            }
        }
    }

    /** @Then 两次失败文案完全一致 */
    public function bothFailureReasonsEqual(): void
    {
        if (count($this->results) < 2) {
            throw new RuntimeException('场景内应已有两次校验');
        }
        [$a, $b] = array_slice($this->results, -2);
        if ($a->reason === null || $a->reason !== $b->reason) {
            throw new RuntimeException('I7 模糊化：两类解密失败对外文案应一致，实际 ' . var_export($a->reason, true) . ' vs ' . var_export($b->reason, true));
        }
    }

    // ==================== helpers ====================

    private function build(int $ts, string $nonce, string $level, string $method, ?string $body): void
    {
        $this->buildArgs = [$method, self::PATH, $body, $level, $ts, $nonce];
        $this->draft = $this->merchantClient()->buildRequest(...$this->buildArgs);
        $this->draft2 = null;
    }

    private function merchantClient(): WopClient
    {
        return new WopClient(new WopConfig(
            appKey: 'app_10012481831',
            securityReq: 'WOP-RSA3072-SHA256',
            privateKey: self::keys()['rsa3072']['privatePkcs8B64'],
            peerPublicKey: self::keys()['rsa3072']['publicSpkiB64'],
        ));
    }

    private static function interopClient(string $suite): WopClient
    {
        $keySet = match ($suite) {
            'WOP-RSA4096-SHA256' => self::keys()['rsa4096'],
            default => self::keys()['rsa3072'],
        };

        return new WopClient(new WopConfig(
            appKey: 'app_interop_001',
            securityReq: $suite,
            privateKey: $keySet['privatePkcs8B64'],
            peerPublicKey: $keySet['publicSpkiB64'],
        ));
    }

    /** 本仓 reason 常量 → 跨仓 canonical class（与 InteropConformanceTest 同一张映射表）。 */
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

    private function draft(): RequestDraft
    {
        return $this->draft ?? throw new RuntimeException('尚无构建结果');
    }

    private function draft2(): RequestDraft
    {
        return $this->draft2 ?? throw new RuntimeException('尚无第二次构建结果');
    }

    private function assertSignedHeaderListed(string $name): void
    {
        $sign = SignHeader::parse((string) $this->draft()->header('x-wop-sign'));
        if (!in_array($name, $sign->signedHeaders, true)) {
            throw new RuntimeException("{$name} 应列入 signedHeaders（I1），实际: " . implode(';', $sign->signedHeaders));
        }
    }

    /** @return array<string, mixed> */
    private static function keys(): array
    {
        return self::vectors()['keys'];
    }

    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        if (self::$vectors === null) {
            $decoded = json_decode((string) file_get_contents(self::VECTORS_PATH), true);
            if (!is_array($decoded)) {
                throw new RuntimeException('fixture 解析失败: ' . self::VECTORS_PATH);
            }
            self::$vectors = $decoded;
        }

        return self::$vectors;
    }

    /** @return array<string, mixed> */
    private static function interopCase(string $id): array
    {
        if (self::$interop === null) {
            $decoded = json_decode((string) file_get_contents(self::INTEROP_PATH), true);
            if (!is_array($decoded)) {
                throw new RuntimeException('interop fixture 解析失败: ' . self::INTEROP_PATH);
            }
            self::$interop = $decoded;
        }
        foreach (self::$interop['cases'] as $case) {
            if ($case['id'] === $id) {
                return $case;
            }
        }
        throw new RuntimeException('interop 样本不存在: ' . $id);
    }

    private static function b64uDecode(string $s): string
    {
        $decoded = base64_decode(strtr($s, '-_', '+/'), true);
        if ($decoded === false) {
            throw new RuntimeException('非法 base64url: ' . $s);
        }

        return $decoded;
    }

    /** behat 引号参数兜底剥壳（双引号由 behat 剥，单引号各版本行为不一）。 */
    private static function arg(string $value): string
    {
        return (string) preg_replace('/^(["\'])(.*)\1$/s', '$2', $value);
    }
}
