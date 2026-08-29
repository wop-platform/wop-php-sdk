# wop-php-sdk 变异测试报告

- 分母口径：KILLED + SURVIVED（INVALID 语法破坏排除）
- 总变异体：494（killed 448 / survived 46 / invalid 0）
- **击杀率 MSI = 90.69%**（448/494）

| 算子 | 变异 | killed | survived | invalid | 击杀率 |
|---|---|---|---|---|---|
| arith-minus | `-`→`+` | 9 | 2 | 0 | 81.8% |
| arith-plus | `+`→`-` | 6 | 0 | 0 | 100.0% |
| bit-xor | `^`→`|` | 2 | 0 | 0 | 100.0% |
| bool-flip | true↔false | 18 | 7 | 0 | 72.0% |
| eq-neg | `===`→`!==` | 50 | 1 | 0 | 98.0% |
| int-plus1 | 整数 n→n+1 | 62 | 12 | 0 | 83.8% |
| int-zero | 整数 n→0 | 65 | 9 | 0 | 87.8% |
| logic | `&&`↔`||` | 23 | 3 | 0 | 88.5% |
| neq-neg | `!==`→`===` | 32 | 0 | 0 | 100.0% |
| not-del | `!x`→`x` | 14 | 0 | 0 | 100.0% |
| rel-gt | `>`→`>=` | 4 | 0 | 0 | 100.0% |
| rel-gte | `>=`→`>` | 4 | 0 | 0 | 100.0% |
| rel-lt | `<`→`<=` | 1 | 2 | 0 | 33.3% |
| rel-lte | `<=`→`<` | 4 | 1 | 0 | 80.0% |
| str-empty | 字符串→`''` | 154 | 9 | 0 | 94.5% |

## 存活变异体（survived，人工复核等价性）
- `src/Aes256Gcm.php:43` logic：`||` → `&&`
- `src/Aes256Gcm.php:43` rel-lt：`<` → `<=`
- `src/Base64Url.php:50` bool-flip：`true` → `false`
- `src/Base64Url.php:56` int-plus1：`90` → `91`
- `src/Base64Url.php:59` int-plus1：`122` → `123`
- `src/Base64Url.php:62` int-plus1：`57` → `58`
- `src/ContentDigest.php:38` logic：`||` → `&&`
- `src/ContentDigest.php:38` int-zero：`1` → `0`
- `src/ContentDigest.php:43` eq-neg：`===` → `!==`
- `src/ContentDigest.php:44` bool-flip：`true` → `false`
- `src/EncryptHeader.php:41` int-zero：`1` → `0`
- `src/EncryptedEnvelope.php:30` int-plus1：`512` → `513`
- `src/RsaOaep.php:42` int-zero：`7` → `0`
- `src/RsaOaep.php:73` arith-minus：`-` → `+`
- `src/RsaOaep.php:73` arith-minus：`-` → `+`
- `src/RsaOaep.php:73` int-zero：`1` → `0`
- `src/RsaOaep.php:82` rel-lt：`<` → `<=`
- `src/RsaOaep.php:100` str-empty：`'RSA 私钥解析失败: '` → `''`
- `src/RsaSigner.php:70` str-empty：`'RSA 公钥解析失败（应为 SPKI PEM 或 Base64）: '` → `''`
- `src/SignHeader.php:38` bool-flip：`false` → `true`
- `src/SignHeader.php:38` logic：`||` → `&&`
- `src/SignHeader.php:38` rel-lte：`<=` → `<`
- `src/SignHeader.php:43` int-zero：`1` → `0`
- `src/Suite.php:54` bool-flip：`true` → `false`
- `src/Suite.php:54` bool-flip：`true` → `false`
- `src/Transport/CurlTransport.php:17` int-plus1：`65536` → `65537`
- `src/Transport/CurlTransport.php:17` int-zero：`65536` → `0`
- `src/Transport/CurlTransport.php:37` int-plus1：`30` → `31`
- `src/Transport/CurlTransport.php:37` int-zero：`30` → `0`
- `src/Transport/CurlTransport.php:47` int-plus1：`1` → `2`
- `src/Transport/CurlTransport.php:47` int-zero：`1` → `0`
- `src/Transport/CurlTransport.php:75` int-plus1：`1` → `2`
- `src/Transport/GuzzleTransport.php:19` int-plus1：`65536` → `65537`
- `src/Transport/GuzzleTransport.php:25` str-empty：`'timeout'` → `''`
- `src/Transport/GuzzleTransport.php:25` int-plus1：`30` → `31`
- `src/Transport/GuzzleTransport.php:25` int-zero：`30` → `0`
- `src/Transport/GuzzleTransport.php:34` str-empty：`'stream'` → `''`
- `src/Transport/GuzzleTransport.php:34` bool-flip：`true` → `false`
- `src/Transport/GuzzleTransport.php:42` str-empty：`', '` → `''`
- `src/Transport/GuzzleTransport.php:73` int-plus1：`1` → `2`
- `src/WopClient.php:149` str-empty：`'响应套件 '` → `''`
- `src/WopClient.php:149` str-empty：`' 与客户端配置 '` → `''`
- `src/WopClient.php:161` bool-flip：`true` → `false`
- `src/WopClient.php:183` str-empty：`' 字节与套件 '` → `''`
- `src/WopClient.php:280` str-empty：`'已签名头 '` → `''`
- `src/WopClient.php:290` int-plus1：`1000` → `1001`
