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

    public static class Builder
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

        public function __construct()
        {
            $this->httpClient = HttpClientSettings::defaults();
        }

        public function appKey(string $appKey): self
        {
            $this->appKey = $appKey;
            return $this;
        }

        public function suite(string $suite): self
        {
            $this->suite = $suite;
            return $this;
        }

        public function merchantPrivateKey(string $merchantPrivateKey): self
        {
            $this->merchantPrivateKey = $merchantPrivateKey;
            return $this;
        }

        public function platformPublicKey(string $platformPublicKey): self
        {
            $this->platformPublicKey = $platformPublicKey;
            return $this;
        }

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

        public function expiredSeconds(int $expiredSeconds): self
        {
            $this->expiredSeconds = $expiredSeconds;
            return $this;
        }

        public function httpClient(?HttpClientSettings $httpClient): self
        {
            $this->httpClient = $httpClient ?? HttpClientSettings::defaults();
            return $this;
        }

        public function transport(?TransportInterface $transport): self
        {
            $this->transport = $transport;
            return $this;
        }

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
}
