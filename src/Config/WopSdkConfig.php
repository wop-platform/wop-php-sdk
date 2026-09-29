<?php

declare(strict_types=1);

namespace Wop\Sdk\Config;

use Wop\Sdk\Transport\TransportInterface;
use Wop\Sdk\WopClient;

/**
 * 配置不可变快照（§3，camelCase 字段与 JSON 一致）。
 */
final class WopSdkConfig
{
    /**
     * @param list<string> $backupServerRoots
     */
    public function __construct(
        public readonly string $appKey,
        public readonly string $suite,
        public readonly string $merchantPrivateKey,
        public readonly string $platformPublicKey,
        public readonly string $serverRoot,
        public readonly array $backupServerRoots,
        public readonly int $expiredSeconds,
        public readonly HttpClientSettings $httpClient,
        public readonly ?TransportInterface $transport = null,
    ) {
    }

    /** K16：日志/toString 私钥打码。 */
    public function __toString(): string
    {
        return 'WopSdkConfig[appKey=' . $this->appKey
            . ', suite=' . $this->suite
            . ', merchantPrivateKey=****, platformPublicKey=****'
            . ', serverRoot=' . $this->serverRoot
            . ', backupServerRoots=' . json_encode($this->backupServerRoots, JSON_UNESCAPED_UNICODE)
            . ', expiredSeconds=' . $this->expiredSeconds
            . ', httpClient=' . json_encode([
                'connectTimeout' => $this->httpClient->connectTimeout,
                'readTimeout' => $this->httpClient->readTimeout,
                'maxRetryCount' => $this->httpClient->maxRetryCount,
            ], JSON_UNESCAPED_UNICODE)
            . ']';
    }

    /** 程序化构造（K11），build() 执行与 JSON 路径等价的 §3.4 校验。 */
    public static function builder(): Builder
    {
        return new Builder();
    }
}

/** Builder（K11）：链式赋值全字段后 build() 执行与 JSON 等价的 §3.4 校验。 */
final class Builder
{
    private ?string $appKey = null;
    private ?string $suite = null;
    private ?string $merchantPrivateKey = null;
    private ?string $platformPublicKey = null;
    private ?string $serverRoot = null;
    /** @var list<string> */
    private array $backupServerRoots = [];
    private int $expiredSeconds = WopClient::DEFAULT_EXPIRED_SECONDS;
    private HttpClientSettings $httpClient;
    private ?TransportInterface $transport = null;

    /** Builder 入口：全字段缺省，链式赋值后 build() 执行 §3.4 等价校验（K11）。 */
    public function __construct()
    {
        $this->httpClient = HttpClientSettings::defaults();
    }

    /** 设置商户 appKey（x-wop-appkey）。 */
    public function appKey(string $appKey): self
    {
        $this->appKey = $appKey;
        return $this;
    }

    /** 设置算法套件标识（securityReq）。 */
    public function suite(string $suite): self
    {
        $this->suite = $suite;
        return $this;
    }

    /** 设置商户私钥材料（PKCS#8，PEM 或 Base64 单行）。 */
    public function merchantPrivateKey(string $merchantPrivateKey): self
    {
        $this->merchantPrivateKey = $merchantPrivateKey;
        return $this;
    }

    /** 设置平台公钥材料（X.509 SPKI，PEM 或 Base64 单行）。 */
    public function platformPublicKey(string $platformPublicKey): self
    {
        $this->platformPublicKey = $platformPublicKey;
        return $this;
    }

    /** 设置主网关根地址（HTTPS 绝对 URL，含 context-path）。 */
    public function serverRoot(string $serverRoot): self
    {
        $this->serverRoot = $serverRoot;
        return $this;
    }

    /** @param list<string>|null $backupServerRoots */
    public function backupServerRoots(?array $backupServerRoots): self
    {
        $this->backupServerRoots = $backupServerRoots ?? [];
        return $this;
    }

    /** 设置出向签名有效窗口（秒，须为正整数）。 */
    public function expiredSeconds(int $expiredSeconds): self
    {
        $this->expiredSeconds = $expiredSeconds;
        return $this;
    }

    /** 设置全局 HTTP 客户端参数（null → 缺省 10000/30000/3）。 */
    public function httpClient(?HttpClientSettings $httpClient): self
    {
        $this->httpClient = $httpClient ?? HttpClientSettings::defaults();
        return $this;
    }

    /** 显式注入传输（缺省走传输发现，§7.2）。 */
    public function transport(?TransportInterface $transport): self
    {
        $this->transport = $transport;
        return $this;
    }

    /** 产出不可变配置快照（校验在加载/构造路径执行，§3.4）。 */
    public function build(): WopSdkConfig
    {
        $raw = new WopSdkConfig(
            $this->appKey ?? '',
            $this->suite ?? '',
            $this->merchantPrivateKey ?? '',
            $this->platformPublicKey ?? '',
            $this->serverRoot ?? '',
            $this->backupServerRoots,
            $this->expiredSeconds,
            $this->httpClient,
            $this->transport,
        );
        return ConfigValidator::validateAndNormalize($raw);
    }
}
