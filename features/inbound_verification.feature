# language: zh-CN
功能: 平台响应与回调验证
  商户验证网关同步响应与异步回调（spec F6、概念 API）。
  样本取自 wop-specs interop 冻结报文，不复用被测 SDK 出向代码构造（D5 纪律）。

  场景: 平台 L0 签名响应校验通过
    当 商户收到 interop 样本 "p07" 的响应
    那么 校验通过且明文还原

  场景: 平台 L2 加密响应解密通过
    当 商户收到 interop 样本 "p09" 的响应
    那么 校验通过且明文还原

  场景: 签名后线上体被篡改的响应按摘要不匹配拒绝
    当 商户收到 interop 样本 "n02-wire-tampered-after-signing" 的响应
    那么 校验失败
    而且 失败分类为 "digest-mismatch"

  场景: 密文字符损坏的 L2 响应按解密失败拒绝
    当 商户收到 interop 样本 "n01-encrypted-char-damage" 的响应
    那么 校验失败
    而且 失败分类为 "decrypt-failed"

  场景: digest 未列入 signedHeaders 的响应被拒绝
    当 商户收到 interop 样本 "n10-digest-not-signed" 的响应
    那么 校验失败
    而且 失败分类为 "protocol"

  场景: 跨路径重放的响应被拒绝
    当 商户收到 interop 样本 "n16-replay-cross-path" 的响应
    那么 校验失败
    而且 失败分类为 "verify-failed"

  场景: 异步回调按 URL path 验证且 query 不参与
    当 商户通过回调地址 "https://merchant.example.com/gateway/interop.echo?ticket=abc" 验证 interop 样本 "p07"
    那么 校验通过且明文还原
