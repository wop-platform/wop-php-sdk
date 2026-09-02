# 贡献指南（WOP PHP SDK）

## 1. 欢迎与定位

本仓库是 WOP 网关**商户侧官方 PHP SDK**（`wop-platform/wop-php-sdk`），实现协议核心
（结构化签名 / 内容摘要 / L2 数字信封 / 验签解密顺序）与可插拔 HTTP 传输适配器。

所有功能面与工程约定对齐 [WOP 商户 SDK 统一规格 Spec v1.0-ratified]
(https://github.com/wop-platform/gtsp-wop-gateway/blob/main/docs/wop-sdk-spec.md)
（功能面 F1–F9、验收 A1–A7、工程约定 §4）。**协议语义冲突时以 spec 为准，不得以本仓既有实现为由顺延 spec 条款**；
发现冲突请在 issue 中上报。

## 2. 开发环境

| 项 | 要求 |
|----|------|
| PHP | ≥ 8.2（CI 矩阵：8.2 / 8.3 / 8.4 / 8.5） |
| Composer | 2.x |
| 扩展 | `openssl`（L2 AES-256-GCM bulk 加解密）、`curl`（CurlTransport 默认适配器） |
| 运行时密码库 | `phpseclib/phpseclib ^3.0`（**唯一** RSA 签名 / OAEP 路径） |
| 测试 | PHPUnit `^11.0 \|\| ^12.0`（dev） |
| 覆盖率 | Xdebug 3（`--path-coverage`；pcov 无路径级分支覆盖，不适用） |

> OAEP 钉子（F2）：RSA-OAEP 必须显式双 SHA-256 + 空 label，**必须走 phpseclib**——
> PHP openssl 扩展的 OAEP MGF1 写死 SHA-1，不满足协议。禁止引入第二条 RSA/OAEP 路径。

## 3. 构建与测试

命令与 `.github/workflows/ci.yml` 完全一致：

```bash
# 安装依赖
composer install --no-interaction --no-progress

# 向量 fixture 完整性（与网关真源字节级比对；离线时退回本地副本并告警）
curl -fsSL -o /tmp/crypto-vectors.json \
  https://raw.githubusercontent.com/wop-platform/gtsp-wop-gateway/main/docs/crypto-vectors.json \
  || cp tests/fixtures/crypto-vectors.json /tmp/crypto-vectors.json
cmp tests/fixtures/crypto-vectors.json /tmp/crypto-vectors.json \
  || echo "fixture 与真源不一致（离线环境跳过远端比对）"

# 测试（含黄金向量 conformance 套件）
vendor/bin/phpunit

# 覆盖率 + 门禁（行 + 分支均 ≥ 98%，当前基线 100.00% / 100.00%，目标保持 100%）
XDEBUG_MODE=coverage php -d memory_limit=2G vendor/bin/phpunit \
  --path-coverage --coverage-php coverage/cov.php \
  --coverage-xml coverage/xml --coverage-html coverage/html
php .ci/coverage-gate.php
```

覆盖率门禁（`.ci/coverage-gate.php`）读取 `--coverage-xml`（行）与 `coverage/cov.php` 快照（分支），
**行与分支任一低于 98% 即非零退出**（spec A3/A4）。PR 必须全绿才可合入。

## 4. 黄金向量纪律

`tests/fixtures/crypto-vectors.json` 是协议正确性的**唯一锚**（向量真源为网关仓
`gtsp-wop-gateway/docs/crypto-vectors.json` 的全量副本）：

- **禁止手改** fixture。CI 在每次构建时将其与网关真源做字节级 `cmp` 比对。
- 新增协议行为（新套件 / 新格式规则）：必须先在网关真源落地向量，再同步副本到本仓，
  并在测试中**全量消费**（正向量字节级断言）。
- 负向量（tamper 篡改 / 跨套件族 / 错格式：双空格、大写 hex、带 `=` 的 base64url、
  mgf1-sha1 陷阱密文等）必须有对应"必须拒绝"断言（spec A2 / F8）。
- 修改 `src/` 协议语义而不同步向量 = PR 直接拒绝。

## 5. 编码规范

- PHP 惯例：`declare(strict_types=1)`、PSR-4 自动加载（`Wop\Sdk\` → `src/`）、PSR-12 风格、
  PHP ≥ 8.2 语法（构造器属性提升、readonly、枚举等按需使用）。
- 功能面对齐（spec §1.3）：
  - **F1** 套件配置与解析：`securityReq` 三套件；跨族 / 非法值明确拒绝；
  - **F2** canonicalRequest：5 段 `\n` 拼接；header 值 Java-URLEncoder 语义（空格→`%20`）；
  - **F3** 结构化 `x-wop-sign`：商户私钥加签 / 平台公钥验签（响应与回调）；
  - **F4** `x-wop-content-digest`：`alg 小写hex` 恰一空格；无 body 缺席（D2）；有 body 必传必入签（I1）；
  - **F5** L2 数字信封：AES-256-GCM（密文 `ciphertext||tag` 尾拼）；DEK 载荷 `AES-256-GCM$b64url(key)$b64url(iv)`；
    RSA-OAEP 显式双 SHA-256 + 空 label；
  - **F6** 响应/回调校验顺序固定：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密（I2/I3）；
  - **F7** 线上字节格式：base64url 无填充（**拒收 `=`**）；
  - **F9** 防重放辅助：CSPRNG nonce、毫秒时间戳、expiredSeconds 组装；
  - **I7** 错误模糊化：验签 / 解密失败对外文案固定（「签名验证失败」「解密失败"），
    不泄露原因细节；配置 / 解析 / 格式类错误抛 `WopException` 且消息语义明确。
- 测试代码建议以 `// spec:<ID>` 标注对应条款（如 `// spec:F6`、`// spec:I7`），建立条款 → 测试的 grep 索引。

## 6. 提交规范

Conventional commits，body 允许 / 鼓励中文：

```
feat: L2 信封支持 …
fix: digest 头双空格 …
test: 补 mgf1-sha1 陷阱密文负向量
docs: README 增补 …
chore: 升级 phpseclib …
```

一次提交一件事；`feat`/`fix` 触及协议语义时 body 中注明对应 spec 条款（D# / I# / F#）。

## 7. PR 流程

1. 从 `main` 切分支开发，PR 目标分支 `main`；
2. CI 必须全绿：PHPUnit（PHP 8.2–8.5 矩阵）+ 覆盖率门禁（行/分支 ≥ 98%）+ 向量 fixture 字节级比对；
3. reviewer 复核：协议语义变更须对照 spec 条款逐条核对（不接受"设计取舍"式偏离）；
4. 合入即视为对 spec 对齐与向量合规的确认。

## 8. 发布流程

- 打 tag 即发布：推送 `vX.Y.Z` tag 触发 [.github/workflows/release.yml](.github/workflows/release.yml)
  （`composer validate` + `composer install` + 向量完整性 + `vendor/bin/phpunit` 全绿）；
- **Packagist 通过 GitHub webhook 自动同步 tag**——tag 推送后 `wop-platform/wop-php-sdk`
  新版本即出现在 Packagist，**无需任何发布凭证**（仓库与 workflow 中不出现 token 明文）；
- 版本号从 git tag 读取（composer.json 不维护 version 字段节奏，以 tag 为准）；
- 打 tag 前置条件：`main` 上 CI 全绿；仅从全绿 `main` 提交打 tag，避免 Packagist 同步到未验证版本；
- 发布失败（release workflow 红）时：删除远端 tag 阻止扩散，修复后重新打 tag。
