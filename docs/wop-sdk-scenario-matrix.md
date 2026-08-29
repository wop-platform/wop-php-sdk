# wop-php-sdk 商户使用场景测试矩阵

> 依据：`wop-specs/sdk/wop-sdk-spec.md`（v1.0-ratified + 附录 D 勘误）
> 方法：从**商户接入 WOP 网关的真实使用旅程**出发，映射 spec F1–F9 / 概念 API / 附录 D 纪律，
> 形成「使用场景 → 协议条款 → 可观察行为 → 测试资产」四层矩阵。
> 测试资产三轨：PHPUnit（单元/协议/向量/interop）、Behat Gherkin（端到端使用场景）、变异测试（断言强度）。

## 0. 定位（场景推导的起点）

SDK 是**商户侧**官方客户端库（spec §1）：出向把签名/摘要/数字信封封装为 `buildRequest → RequestDraft`，
入向把验签→解密封装为 `verifyResponse / verifyCallback → VerifyResult`；传输层可插拔（Q1）。
网关（gtsp-wop-gateway）是协议对端：验商户签、解商户信封、回签平台响应。
因此商户旅程 = **配置 → 出向请求（3 种形态）→ 入向验证（2 种来源）→ 遭遇攻击/畸形 → 错误处理 → 传输接入 → 跨仓一致**。

## 1. 场景矩阵

### UC1 商户首次接入：套件与密钥配置

商户拿到 appKey、密钥对与平台公钥后装配 `WopConfig`。配置错误必须在装配期暴露，而非请求期。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 1.1 | RSA3072 套件装配成功 | F1/§2 | `Suite::parse` 产出 keyLength=3072、digestLabel=sha-256、dekAlg=AES-256-GCM | `SuiteTest::testParseRsa3072` | 商户配置.feature:S1 |
| 1.2 | RSA4096 套件装配成功 | F1 | keyLength=4096，签名恒 683 字符 | `SuiteTest::testParseRsa4096`、`RsaSignerTest::testSignRsa4096…` | （同 1.1 参数化覆盖） |
| 1.3 | SM2-SM3 明确「暂未支持」 | F1/Q7 | 错误文案含路线图指引，非裸异常 | `SuiteTest::testParseSm2Sm3IsRejected…` | 商户配置.feature:S2 |
| 1.4 | 跨族组合拒绝（RSA3072+SM3 等） | F1/§2.3 | 「不支持的算法组合」，与暂未支持语义区分 | `SuiteTest::testCrossFamilyRejected` | 商户配置.feature:S3 |
| 1.5 | 格式非法（空值/前缀/段数）拒绝 | F1 | 「格式错误」解析类 | `SuiteTest::testMalformedRejected` | 商户配置.feature:S4 |
| 1.6 | 私钥垃圾输入 → 明确配置错误 | §2/I7 边界 | 加签路径抛「RSA 私钥解析失败」（明确类，不模糊） | `RsaSignerTest::testKeyParseFailures` | —（单元轨道覆盖） |

### UC2 商户发起明文业务请求（L0 POST）

典型：物流下单/查询等非敏感数据。商户只给 method/path/body，SDK 产全套协议头。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 2.1 | 全套协议头产出 | F3/概念 API | appkey/timestamp/nonce/sign 头齐备，signedHeaders 排序 | `WopClientTest::testBuildRequestL0WithBody` | 出向请求.feature:S1 |
| 2.2 | 有 body 必产 digest 且入签 | F4/D2/I1 | `sha-256 <hex>` 恰一空格；digest ∈ signedHeaders | 同上 | 出向请求.feature:S1 |
| 2.3 | 签名覆盖 canonicalRequest | F2/F3 | 5 段 `\n`、Java-URLEncoder 语义（空格→%20、`*` 保留、`~`→%7E） | `CanonicalRequestTest::*`、向量 sign | 出向请求.feature:S1（间签验证） |
| 2.4 | 同输入幂等 | §2 确定性 | 固定 nonce/timestamp 下 headers+wireBody 逐字节相同 | `testBuildRequestIsDeterministicForL0` | 出向请求.feature:S4 |
| 2.5 | 随机字段防重放 | F9 | 缺省时 nonce=32 hex 互异、timestamp=13 位毫秒 | `testF9DefaultsAreRandom` | 出向请求.feature:S5 |

### UC3 商户发起查询请求（GET 无 body）

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 3.1 | 无 body digest 缺席 | D2 | 不携带 x-wop-content-digest，也不入 signedHeaders | `testBuildRequestGetWithoutBodyOmitsDigest` | 出向请求.feature:S2 |
| 3.2 | 入向对称：无 body 携 digest 被拒 | D2 反向 | verify 失败「无响应体不应携带…」 | interop n15 | 篡改拒绝.feature（interop n15） |

### UC4 商户发起敏感数据请求（L2 信封）

典型：金额、证件号等。SDK 全文加密并包装 DEK。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 4.1 | 线上体为信封 JSON | F5/D3 | `{"encrypted":"<b64url>"}`，容忍未知字段 | `testBuildRequestL2Envelope`、`InteropConformanceTest` | 出向请求.feature:S3 |
| 4.2 | DEK 载荷与 OAEP 包装 | F5/§6 | `alg$b64u(key)$b64u(iv)`；RSA-OAEP 显式双 SHA-256+空 label | `DekPayloadTest::*`、`RsaOaepTest::*`（含 mgf1-sha1 陷阱负向量） | 出向请求.feature:S3 |
| 4.3 | encrypt 头入签 | I1 | `L2;dek=…` ∈ signedHeaders | `testBuildRequestL2Envelope` | 出向请求.feature:S3 |
| 4.4 | 对端（平台私钥）可解 | F5 | 信封→DEK 解包→alg 比对→bulk 解密还原明文 | `testBuildRequestL2Envelope`（平台视角解开） | 出向请求.feature:S3 |
| 4.5 | bulk 密码学正确 | F5/F8 | AES-256-GCM 32B key/12B IV/tag 尾拼，字节级=向量 | `Aes256GcmTest::*` | —（向量轨道） |

### UC5 商户验证平台同步响应

商户收到网关响应（L0 明文/L2 密文），先验签后解密。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 5.1 | L0 响应验签通过 | F6 | ok=true，plaintext=body；混合大小写头名可验（P7） | `testVerifyResponseL0HappyPath`、interop p07-p13 | 入向验证.feature:S1 |
| 5.2 | L2 响应解密通过 | F6 | 验签→digest→DEK→alg→bulk 全过后还原明文 | `testVerifyResponseL2HappyPath` | 入向验证.feature:S2 |
| 5.3 | 校验顺序固定 | F6/I2/I3 | 先验签（篡改签名时即使 digest 也坏，只报签名失败）；digest 先于解密；alg 族比对先于 bulk | `testVerifyResponseSignatureCheckedBeforeDigest` 等 4 个顺序场景 | —（单元轨道，行为依赖密码学耦合，Gherkin 不重复） |
| 5.4 | 响应套件与配置一致性 | F1/F6 | 套件不符 → 明确拒绝 | `testVerifyResponseRejectsSmSuite`、interop n11 | — |

### UC6 商户验证平台异步回调

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 6.1 | 回调 canonical URI 取 path | §2/概念 API | `verifyCallback` 用回调 URL 的 path 验签 | `testVerifyCallbackUsesCallbackPath` | 入向验证.feature:S6 |
| 6.2 | URL 带 query 不参与验签 | §2 | query 剥离，path 不变即通过 | 同上扩展 | 入向验证.feature:S6 |

### UC7 商户遭遇篡改与重放（攻击面）

测试即攻击者：冻结报文上做最小篡改，SDK 必须拒。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 7.1 | 签名后线上体被篡改 | F4/F6/A2 | digest-mismatch | interop n02、`testVerifyResponseDigestCheckedBeforeDecryption` | 入向验证.feature:S3 |
| 7.2 | 密文字符损坏 | F5/A2 | decrypt-failed | interop n01 | 入向验证.feature:S4 |
| 7.3 | 签名段畸形（`=` 填充/63B/65B） | F7/A2 | protocol 拒 | interop n06-n08、`Base64UrlTest::*` | —（向量轨道全量） |
| 7.4 | 跨路径重放 | F9/A2 | 换 path 验签失败 verify-failed | interop n16 | 入向验证.feature:S5 |
| 7.5 | 已签名头被剥离 | F6 | protocol 拒（「已签名头…缺失」） | `testVerifyResponseSignedHeaderStripped…`、interop n14 | — |
| 7.6 | DEK 跨族/长度/信封缺字段 | D8/A2 | alg-mismatch / decrypt-failed / protocol | interop n04/n13/n12 | 错误纪律.feature:S2 |

### UC8 商户遭遇协议违规（畸形输入）

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 8.1 | 有 body 无 digest 头 | D2 | digest-mismatch | interop n09、`testVerifyResponseMissingDigestHeaderRejected` | 错误纪律.feature:S2（n09） |
| 8.2 | digest 未入签 | I1 | protocol 拒 | interop n10 | 入向验证.feature:S4 变体（n10） |
| 8.3 | digest 标签跨族/大写 hex/双空格 | F4/I5 | 格式错误 | `ContentDigestTest::testFormatRules`（formatRules 全量） | — |
| 8.4 | base64url 非规范尾随位 | D1/F7 | `aE`/`TWF` 拒、`AA`/`TWE` 收 | `Base64UrlTest`（12 条 formatRules 三件套） | — |

### UC9 错误纪律：模糊与明确的分界（I7）

商户侧日志/对外提示不得泄露密码学失败细节；协议结构知识保持明确。

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 9.1 | DEK 解包失败 ≡ GCM 解密失败 | I7 | 两类失败同为「解密失败」 | `testVerifyResponseI7ObfuscatesDecryptFailures` | 错误纪律.feature:S1 |
| 9.2 | 验签失败不区分细节 | I7 | 篡改签名/错公钥 reason 一致 | `testVerifyResponseSignatureFailureIsUniform` | — |
| 9.3 | 协议类错误保持明确 | 10.2 | n03/n06/n10 等 → protocol 类文案 | `InteropConformanceTest::testVerifyNegativeClassification` | 错误纪律.feature:S2 |

### UC10 传输接入：官方适配器或自带栈

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 10.1 | RequestDraft 直接消费 | Q1 | headers+wireBody 自足，商户自带栈免依赖 | `RequestDraft::header`（含大小写不敏感） | — |
| 10.2 | curl/Guzzle 适配器 roundtrip | Q1 | 内置服务器真实 HTTP 往返 | `TransportTest::testCurl/GuzzleTransportRoundtrip` | — |
| 10.3 | 响应体 11MB 流式限额 | D4 | 读取中超限即断流；恰等于限额通过 | `testCurl/GuzzleTransportRejectsOversized…`/`…AcceptsExactLimit…` | — |

### UC11 跨仓互操作（字节级）

| # | 场景 | spec 条款 | 可观察行为 | PHPUnit | Behat 场景 |
|---|------|-----------|-----------|---------|-----------|
| 11.1 | build 方向字节复现 | interop/v1 | 随机流合同下 wireBody/headers 与 Go 基线逐字节同 | `testBuildConformanceByteExact`（4 条 RSA） | — |
| 11.2 | verify 方向冻结样本 | interop/v1/D5 | 正/负 21 条分类对账 | `testVerifyPositive/Negative…` | 入向验证.feature（复用冻结样本） |

## 2. 三轨测试资产映射

- **PHPUnit**：单元语义 + 黄金向量 + interop 合同 + 边界/消息钉死（本次补强后 187 用例），覆盖矩阵全部行为行。
- **Behat Gherkin（新增 18 场景 / 4 feature）**：把 UC1/UC2/UC3/UC4/UC5/UC6/UC7/UC9 中
  「商户可直接叙述」的行为编为可读场景；密码学字节级与传输层细节留在单元/向量轨道（Gherkin 不重复造轮子）。
  入向场景全部消费 interop 冻结样本（D5：不复用被测 SDK 出向代码构造平台响应）。
- **变异测试（新增脚本 `.ci/mutation-run.php`）**：对 `src/` 注入 15 类 token 级算子，
  验证上述断言的真实击杀力（防「全绿但弱断言」），报告见 `docs/mutation-report.md`。

## 3. 覆盖率缺口（本次实测）

实测（xdebug 3.5.3 `--path-coverage` + `.ci/coverage-gate.php`）：

- 接手时工作区（含未提交 src 变更，可执行行 344→467）：**行 462/467 = 98.93%，分支 390/395 = 98.73%**。
- 缺口定位（`.ci/gap-report.php`，5 行/5 分支同源，共 4 条路径）：
  `DekPayload::decode` 未知 alg（L70）、iv 长度（L78）；`EncryptHeader::parse` dek 字符集（L48）；
  `WopClient::verify` dek 段 b64url 长度非法（L226-227）。
- 补 4 个负测试后：**行 467/467 = 100.00%，分支 395/395 = 100.00%**（gate exit 0）。
  另修 TransportTest 内置 server 就绪竞争（flaky 会污染变异判定），并补 Transport 边界测试。
