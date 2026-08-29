# language: zh-CN
功能: 错误纪律：模糊与明确的分界
  验签/解密类密码学失败对外模糊（I7），协议结构类错误保持语义明确（10.2）。

  场景: DEK 解包失败与 GCM 解密失败对外同文案
    当 商户收到 interop 样本 "n01-encrypted-char-damage" 的响应
    而且 商户收到 interop 样本 "n13-dek-key-length" 的响应
    那么 两次校验均失败
    而且 两次失败文案完全一致

  场景: 协议类错误保持明确分类
    当 商户收到 interop 样本 "n09-digest-missing" 的响应
    那么 校验失败
    而且 失败分类为 "digest-mismatch"
    当 商户收到 interop 样本 "n03-digest-tag-cross-family" 的响应
    那么 校验失败
    而且 失败分类为 "protocol"
