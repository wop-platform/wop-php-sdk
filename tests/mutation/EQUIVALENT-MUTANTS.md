# 变异测试等价清单（wop-php-sdk）

> 台账口径：基线 46 个点位 → 40 个唯一 (文件,行,算子) 锚（同行同算子多点位合并，
> 如 RsaOaep.php:73 两个 `-` 位点）；锚校验按行级覆盖全部点位。

> 基线：docs/mutation-report.md（494 变异体，MSI 90.69%，46 幸存）。
> 本清单按 wop-specs D6/D7 纪律逐条归档：每条附**锚前缀**（源码行首字符，供
> `scripts/check-equivalent-anchors.py` 每 PR 校验漂移）与**等价论证**。
> 未论证条目一律标 TODO——按 D7，未经论证的等价体**不得**从击杀率分母剔除，
> 清单先行只为建立漂移防线与复核台账。
>
> 论证充分的族（示范）：
> - **str-empty 诊断文案族**：错误 message 前缀/连接段置空——文案非对外契约
>   （I7 明确类仅保证 ErrorCode 语义；文案漂移属 spec 允许的实现自由），
>   与 wop-go-sdk 口径B、wop-dotnet-sdk 错误契约测试的例外段同源。
>   该族剔除与否由仓 owner 决策后统一口径（建议：补 message 关键词断言后杀掉，
>   而非剔除——见 wop-dotnet-sdk ErrorContractTests 模式）。

| # | 位置 | 算子 | 锚 | 论证 |
|---|------|------|----|------|
| 1 | `ContentDigest.php:38` | logic | `{` | TODO: owner 复核论证 |
| 2 | `ContentDigest.php:38` | int-zero | `{` | TODO: owner 复核论证 |
| 3 | `ContentDigest.php:43` | eq-neg | `[$label, $hex] = $parts;` | TODO: owner 复核论证 |
| 4 | `ContentDigest.php:44` | bool-flip | `$expectedLabel = $suite?` | TODO: owner 复核论证 |
| 5 | `EncryptHeader.php:41` | int-zero | `}` | TODO: owner 复核论证 |
| 6 | `EncryptedEnvelope.php:30` | int-plus1 | `try {` | TODO: owner 复核论证 |
| 7 | `RsaOaep.php:42` | int-zero | `$key = self::rawPublicKe` | TODO: owner 复核论证 |
| 8 | `RsaOaep.php:73` | arith-minus | `$db = $lHash . $ps . "\x` | TODO: owner 复核论证 |
| 9 | `RsaOaep.php:73` | arith-minus | `$db = $lHash . $ps . "\x` | TODO: owner 复核论证 |
| 10 | `RsaOaep.php:73` | int-zero | `$db = $lHash . $ps . "\x` | TODO: owner 复核论证 |
| 11 | `RsaOaep.php:82` | rel-lt | `$t = '';` | TODO: owner 复核论证 |
| 12 | `RsaOaep.php:100` | str-empty | `->withMGFHash(self::HASH` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 13 | `RsaSigner.php:70` | str-empty | `try {` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 14 | `SignHeader.php:38` | bool-flip | `if ($sp === false || $sp` | TODO: owner 复核论证 |
| 15 | `SignHeader.php:38` | logic | `if ($sp === false || $sp` | TODO: owner 复核论证 |
| 16 | `SignHeader.php:38` | rel-lte | `if ($sp === false || $sp` | TODO: owner 复核论证 |
| 17 | `SignHeader.php:43` | int-zero | `$seg = \explode('/', \tr` | TODO: owner 复核论证 |
| 18 | `Suite.php:54` | bool-flip | `[, $keyAlg, $digestAlg] ` | TODO: owner 复核论证 |
| 19 | `Suite.php:54` | bool-flip | `[, $keyAlg, $digestAlg] ` | TODO: owner 复核论证 |
| 20 | `Transport/CurlTransport.php:17` | int-plus1 | `private const READ_CHUNK` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 21 | `Transport/CurlTransport.php:17` | int-zero | `private const READ_CHUNK` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 22 | `Transport/CurlTransport.php:37` | int-plus1 | `CURLOPT_HTTPHEADER => $h` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 23 | `Transport/CurlTransport.php:37` | int-zero | `CURLOPT_HTTPHEADER => $h` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 24 | `Transport/CurlTransport.php:47` | int-plus1 | `if ($received > self::MA` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 25 | `Transport/CurlTransport.php:47` | int-zero | `if ($received > self::MA` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 26 | `Transport/CurlTransport.php:75` | int-plus1 | `$pos = \strpos($line, ':` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 27 | `Transport/GuzzleTransport.php:19` | int-plus1 | `private const READ_CHUNK` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 28 | `Transport/GuzzleTransport.php:25` | str-empty | `// guzzlehttp/guzzle 为 s` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 29 | `Transport/GuzzleTransport.php:25` | int-plus1 | `// guzzlehttp/guzzle 为 s` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 30 | `Transport/GuzzleTransport.php:25` | int-zero | `// guzzlehttp/guzzle 为 s` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 31 | `Transport/GuzzleTransport.php:34` | str-empty | `'headers' => self::toAss` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 32 | `Transport/GuzzleTransport.php:34` | bool-flip | `'headers' => self::toAss` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 33 | `Transport/GuzzleTransport.php:42` | str-empty | `$responseHeaders = [];` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 34 | `Transport/GuzzleTransport.php:73` | int-plus1 | `$pos = \strpos($line, ':` | TODO: 传输层超时/缓冲常量族——owner 复核（配置面非协议核心，可论证非等价并补测试） |
| 35 | `WopClient.php:149` | str-empty | `return VerifyResult::fai` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 36 | `WopClient.php:149` | str-empty | `return VerifyResult::fai` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 37 | `WopClient.php:161` | bool-flip | `}` | TODO: owner 复核论证 |
| 38 | `WopClient.php:183` | str-empty | `return VerifyResult::fai` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 39 | `WopClient.php:280` | str-empty | `if ($value === null) {` | 诊断文案族（见头部说明）；建议补断言击杀而非剔除 |
| 40 | `WopClient.php:290` | int-plus1 | `{` | TODO: owner 复核论证 |
