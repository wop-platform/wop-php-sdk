# WOP PHP SDK

[![Packagist](https://img.shields.io/packagist/v/wop-platform/wop-php-sdk)](https://packagist.org/packages/wop-platform/wop-php-sdk) [![PHP 8.2+](https://img.shields.io/packagist/php-v/wop-platform/wop-php-sdk)](https://packagist.org/packages/wop-platform/wop-php-sdk) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-php-sdk)](https://github.com/wop-platform/wop-php-sdk/releases)
[![CI](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-php-sdk)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20(line%2Bbranch)-brightgreen)](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml) [![Gherkin](https://img.shields.io/badge/bdd-18%20scenarios-orange)](features/inbound_verification.feature) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-php-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-php-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)


WOP 网关商户侧官方 PHP 客户端库：封装协议核心（结构化签名 / 内容摘要 / L2 数字信封 / 验签解密），
商户无需理解 canonicalRequest、套件推导与线上字节格式即可安全对接。

- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）
- 正确性锚：黄金向量**字节级**断言 + 负向量（tamper/跨族/带 `=` base64url）必须拒绝

## 快速开始

```bash
composer require wop-platform/wop-php-sdk
```

```php
use Wop\Sdk\WopClient;
use Wop\Sdk\WopConfig;
use Wop\Sdk\Transport\CurlTransport;

$client = new WopClient(new WopConfig(
    appKey:         'app_10012481831',
    securityReq:    'WOP-RSA3072-SHA256',
    privateKey:     $merchantPrivateKeyPemOrBase64,   // 己方私钥（出向加签 / 入向 DEK 解包）
    peerPublicKey:  $platformPublicKeyPemOrBase64,    // 平台公钥（响应/回调验签 / DEK 包装）
));

// 1. 构造请求（L0 明文 / L2 数字信封），得到可直接发送的 RequestDraft
$draft = $client->buildRequest('POST', '/gateway/logistics.order.query', $jsonBody, 'L2');

// 2. 任选 Transport 发送（curl 扩展适配器 / Guzzle peer 适配器，或自带 HTTP 栈）
$transport = new CurlTransport();
$response  = $transport->send($draft->method, 'https://gateway.example.com' . $draft->path,
                              $this->toHeaderLines($draft->headers), $draft->wireBody);

// 3. 验证平台响应（验签 → digest 复核 → DEK 解包 → alg 族比对 → 解密，顺序固定）
$result = $client->verifyResponse(
    $this->toArray($response->headers), $response->body, '/gateway/logistics.order.query');
if ($result->ok) {
    $plaintext = $result->plaintext;
}
```

`RequestDraft::headers` 为 `name => value` 关联数组；curl 需要 `"$name: $value"` 头行、
Guzzle 适配器直接接受数组——`GuzzleTransport::send()` 内部完成转换。

## 密钥准备（D12 分发契约）

| 用途 | 格式 |
|------|------|
| RSA 公钥（SPKI） | X.509 SubjectPublicKeyInfo DER 的 Base64 单行，或等价 PEM（`-----BEGIN PUBLIC KEY-----` 包装） |
| RSA 私钥（PKCS8） | PKCS#8 DER 的 Base64 单行，或等价 PEM（`-----BEGIN PRIVATE KEY-----` 包装） |

- SDK 对 PEM / Base64 单行两种入参等价接受（内部 `phpseclib` 解析并缓存）；
- 签名算法族：`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256`（SHA256withRSA，PKCS#1 v1.5）；
- `SM2` 公钥（`04‖X‖Y` 65B）与 `d` 32B 标量属国密套件，本版不支持（见下方路线图）。

## L0 + L2 示例

**L0（明文 + 摘要 + 签名）**：`buildRequest(method, path, $body, 'L0')` ——
有 body 时自动生成 `x-wop-content-digest: sha-256 <小写hex>`（恰一空格），无 body（GET）则该头缺席；
digest 与 `x-wop-appkey/x-wop-nonce/x-wop-timestamp` 一并进入 signedHeaders（协议不变式 I1）。

**L2（全文数字信封）**：`buildRequest(method, path, $body, 'L2')` ——
CSPRNG 生成 32B DEK + 12B IV，AES-256-GCM 加密 body（密文 = `ciphertext||tag` 尾拼），
DEK 载荷 `AES-256-GCM$b64url(key)$b64url(iv)` 经 RSA-OAEP（**显式双 SHA-256 + 空 label**）包装后
置于 `x-wop-encrypt: L2;dek=<b64url>`；digest 改为对**密文载体**字节计算（D2）。
L2 wire body 恒为 JSON 信封 `{"encrypted":"<base64url 密文>"}`（与网关 CryptoFilter 线上契约一致）；
入向解密时提取 `encrypted` 字段（容忍未知字段），非法结构/缺字段按协议类错误明确拒绝。

**回调验证**：`verifyCallback($headers, $body, $callbackUrl)` —— canonical URI 取回调 URL 的 path。

```php
// 商户回调接收端（POST）
$result = $client->verifyCallback($headers, $body, 'https://merchant.example.com/callback/notify');
```

## 向量自测（conformance）

```bash
composer install
vendor/bin/phpunit                  # 139 项断言全绿（含黄金向量套件）
```

- `tests/fixtures/crypto-vectors.json` 与网关真源逐字节一致（CI 校验）；
- RSA 签名（3072/4096）、OAEP 解包（含 **mgf1-sha1 陷阱密文必须拒**）、AES-256-GCM、
  digest 头组装均为字节级断言；`formatRules` 负向量（双空格/大写 hex/跨族标签/带 `=` base64url）全量消费；
- 覆盖率（xdebug `--path-coverage`）：**行 100.00% / 分支 100.00%**（CI 门禁 ≥98%）。

## 错误处理与模糊化（I7）

- 配置/解析/格式/一致性类错误：抛 `Wop\Sdk\WopException`，消息语义明确（帮助集成自查）；
- 验签失败与解密失败（GCM tag / DEK 解包）：**对外文案固定**为「签名验证失败」「解密失败」，
  不区分原因细节，防 padding-oracle 式信息泄露；调用方仅见 `VerifyResult::reason`。

## 依赖说明

| 依赖 | 角色 |
|------|------|
| `phpseclib/phpseclib ^3.0` | 唯一运行时密码库：RSA 签名 + OAEP（**必须**走它——openssl 扩展 OAEP 的 MGF1 写死 SHA-1，不满足 F2 钉子） |
| `ext-openssl`（suggest） | L2 信封 AES-256-GCM bulk 加解密（tag 独立出参，本 SDK 完成尾拼） |
| `ext-curl`（suggest） | `CurlTransport` 默认适配器 |
| `guzzlehttp/guzzle`（suggest） | `GuzzleTransport` peer 适配器（不污染核心依赖面） |

## 国密路线图（SM2-SM3 套件）

本版（0.1.0）按 SDK spec §1.2（裁决 Q7）**仅支持 RSA 套件**；`WOP-SM2-SM3` 配置与报文
将明确抛出 `WopException("SM2-SM3 套件暂未支持，见 README 路线图")`。

计划中的国密支持（SM3withSM2 裸 r‖s 64B / SM4-GCM / SM2 C1C3C2）将以纯 PHP 实现交付，
黄金向量 fixture 已全量就位（`tests/fixtures/crypto-vectors.json` 的 SM 段当前作为
"必须拒"负测试消费），届时无需变更协议层。欢迎在 issue 中反馈需求优先级。

## License

MIT（见 [LICENSE](LICENSE)）。
