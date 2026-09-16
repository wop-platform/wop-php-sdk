<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use Wop\Sdk\Config\ConfigJsonParser;
use Wop\Sdk\Config\ConfigValidator;
use Wop\Sdk\Config\WopConfigLoader;
use Wop\Sdk\WopException;

/** config-spec P0：配置加载、校验、缓存与极简 JSON 解析器。 */
final class WopConfigLoaderTest extends VectorCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        WopConfigLoader::clearCache();
        WopClientConfigTestHelper::resetDefault();
        $this->tempDir = sys_get_temp_dir() . '/wop-config-test-' . bin2hex(random_bytes(4));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        WopConfigLoader::clearCache();
        WopClientConfigTestHelper::resetDefault();
        $this->removeTree($this->tempDir);
        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV);
        putenv(WopConfigLoader::CONFIG_FILE_ENV);
    }

    public function testLoadValidFixture(): void
    {
        $path = __DIR__ . '/fixtures/valid-wop-config.json';
        $config = WopConfigLoader::loadPath($path);

        $this->assertSame('app_10012481831', $config->appKey);
        $this->assertSame('WOP-RSA3072-SHA256', $config->suite);
        $this->assertSame('https://gw.example.com/gateway', $config->serverRoot);
        $this->assertSame(['https://gw-backup.example.com/gateway'], $config->backupServerRoots);
        $this->assertSame(1800, $config->expiredSeconds);
        $this->assertSame(10000, $config->httpClient->connectTimeout);
    }

    public function testLoadTrimsServerRootTrailingSlash(): void
    {
        $path = $this->writeConfig(['serverRoot' => 'https://gw.example.com/gateway/']);
        $config = WopConfigLoader::loadPath($path);
        $this->assertSame('https://gw.example.com/gateway', $config->serverRoot);
    }

    public function testDuplicateAppKeyRejected(): void
    {
        $json = '{'
            . '"appKey":"a","appKey":"b",'
            . '"suite":"WOP-RSA3072-SHA256",'
            . '"merchantPrivateKey":"' . self::keys()['rsa3072']['privatePkcs8B64'] . '",'
            . '"platformPublicKey":"' . self::keys()['rsa3072']['publicSpkiB64'] . '",'
            . '"serverRoot":"https://gw.example.com/gateway"'
            . '}';
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('配置字段 appKey 重复');
        ConfigJsonParser::parse($json);
    }

    public function testDuplicateServerRootRejected(): void
    {
        $json = '{'
            . '"appKey":"app",'
            . '"suite":"WOP-RSA3072-SHA256",'
            . '"merchantPrivateKey":"' . self::keys()['rsa3072']['privatePkcs8B64'] . '",'
            . '"platformPublicKey":"' . self::keys()['rsa3072']['publicSpkiB64'] . '",'
            . '"serverRoot":"https://gw.example.com/gateway",'
            . '"serverRoot":"https://gw2.example.com/gateway"'
            . '}';
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('配置字段 serverRoot 重复');
        ConfigJsonParser::parse($json);
    }

    public function testMissingRequiredFieldRejected(): void
    {
        $path = $this->writeConfig(['appKey' => null]);
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('配置文件缺少必填项: appKey');
        WopConfigLoader::loadPath($path);
    }

    public function testHttpServerRootRejected(): void
    {
        $path = $this->writeConfig(['serverRoot' => 'http://gw.example.com/gateway']);
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('serverRoot 须为 HTTPS 绝对 URL');
        WopConfigLoader::loadPath($path);
    }

    public function testServerRootQueryFragmentRejected(): void
    {
        $path = $this->writeConfig(['serverRoot' => 'https://gw.example.com/gateway?x=1']);
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('serverRoot 不得含 query 或 fragment');
        WopConfigLoader::loadPath($path);
    }

    public function testBackupServerRootValidationUsesIndex(): void
    {
        $path = $this->writeConfig([
            'backupServerRoots' => ['https://ok.example.com/gateway', 'http://bad.example.com/gateway'],
        ]);
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('backupServerRoots[2] 须为 HTTPS 绝对 URL');
        WopConfigLoader::loadPath($path);
    }

    public function testCacheReturnsSameInstance(): void
    {
        $path = __DIR__ . '/fixtures/valid-wop-config.json';
        $first = WopConfigLoader::loadPath($path);
        $second = WopConfigLoader::loadPath($path);
        $this->assertSame($first, $second);
    }

    public function testClearCacheForcesReload(): void
    {
        $path = __DIR__ . '/fixtures/valid-wop-config.json';
        $first = WopConfigLoader::loadPath($path);
        WopConfigLoader::clearCache();
        $second = WopConfigLoader::loadPath($path);
        $this->assertNotSame($first, $second);
        $this->assertSame($first->appKey, $second->appKey);
    }

    public function testLoadDefaultUsesOverrideEnvFirst(): void
    {
        $path = __DIR__ . '/fixtures/valid-wop-config.json';
        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV . '=' . $path);
        $config = WopConfigLoader::loadDefault();
        $this->assertSame('app_10012481831', $config->appKey);
    }

    public function testExplicitUnreadableConfigFailsFast(): void
    {
        putenv(WopConfigLoader::CONFIG_FILE_OVERRIDE_ENV . '=' . $this->tempDir . '/missing.json');
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('显式配置文件不可读');
        WopConfigLoader::loadDefault();
    }

    public function testClasspathLoadDefaultTemplateFailsOnPlaceholderKeys(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('密钥解析失败');
        WopConfigLoader::load('classpath:config/wopSdkConfigDefault.json');
    }

    public function testToStringMasksPrivateKeys(): void
    {
        $config = WopConfigLoader::loadPath(__DIR__ . '/fixtures/valid-wop-config.json');
        $text = (string) $config;
        $this->assertStringContainsString('merchantPrivateKey=****', $text);
        $this->assertStringContainsString('platformPublicKey=****', $text);
        $this->assertStringNotContainsString(self::keys()['rsa3072']['privatePkcs8B64'], $text);
    }

    public function testJoinUrlPreservesContextPath(): void
    {
        $url = ConfigValidator::joinUrl('https://gw.example.com/gateway', '/gateway/order/create');
        $this->assertSame('https://gw.example.com/gateway/gateway/order/create', $url);
    }

    public function testValidateApiPathRejectsNetworkPathReference(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('path 不得 // 开头');
        ConfigValidator::validateApiPath('//attacker.example/path');
    }

    /** @param array<string, mixed> $overrides */
    private function writeConfig(array $overrides): string
    {
        $base = json_decode((string) file_get_contents(__DIR__ . '/fixtures/valid-wop-config.json'), true);
        $this->assertIsArray($base);
        foreach ($overrides as $key => $value) {
            if ($value === null) {
                unset($base[$key]);
            } else {
                $base[$key] = $value;
            }
        }
        $path = $this->tempDir . '/wopSdkConfig.json';
        file_put_contents($path, json_encode($base, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        return $path;
    }

    private function removeTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($path)) {
                $this->removeTree($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
