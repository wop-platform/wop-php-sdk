# language: zh-CN
功能: 商户出向请求构建
  商户只提供 method/path/body，SDK 产出全套协议头与线上体
  （spec F2/F3/F4/F5/F9、D2/I1、§2 确定性）。

  场景: L0 POST 请求携带全套协议头且 digest 入签
    当 商户以固定时间戳 1774340000000 与 nonce "0123456789abcdef0123456789abcdef" 构建 L0 POST 请求体 '{"k":"v"}'
    那么 请求头 "x-wop-appkey" 值为 "app_10012481831"
    而且 请求头 "x-wop-timestamp" 值为 "1774340000000"
    而且 请求头 "x-wop-nonce" 值为 "0123456789abcdef0123456789abcdef"
    而且 请求携带 digest 头
    而且 digest 头已列入签名头的 signedHeaders
    而且 线上体等于 '{"k":"v"}'

  场景: GET 无 body 请求不携带 digest 头
    当 商户以固定时间戳 1774340000000 与 nonce "0123456789abcdef0123456789abcdef" 构建 L0 GET 请求无 body
    那么 请求不携带 digest 头
    而且 线上体为空串

  场景: L2 请求以数字信封加密线上体且对端可解
    当 商户以固定时间戳 1774340000000 与 nonce "0123456789abcdef0123456789abcdef" 构建 L2 POST 请求体 '{"secret":"薪资"}'
    那么 请求头 "x-wop-encrypt" 以 "L2;dek=" 开头
    而且 线上体为 L2 信封 JSON
    而且 x-wop-encrypt 已列入签名头的 signedHeaders
    而且 平台私钥可解开信封并还原明文 '{"secret":"薪资"}'

  场景: 同输入下构建幂等
    当 商户以固定时间戳 1774340000000 与 nonce "0123456789abcdef0123456789abcdef" 构建 L0 POST 请求体 'same-body'
    而且 商户以相同参数再次构建
    那么 两次构建的签名头完全一致
    而且 两次构建的线上体完全一致

  场景: 缺省随机字段满足防重放格式且互异
    当 商户构建两个 GET 请求且不注入随机量
    那么 两次构建的 nonce 互异
    而且 两次构建的 nonce 均为 32 位小写十六进制
    而且 两次构建的时间戳均为 13 位毫秒
