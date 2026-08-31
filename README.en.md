# WOP PHP SDK

[![Packagist](https://img.shields.io/packagist/v/wop-platform/wop-php-sdk)](https://packagist.org/packages/wop-platform/wop-php-sdk) [![PHP 8.1+](https://img.shields.io/packagist/php-v/wop-platform/wop-php-sdk)](https://packagist.org/packages/wop-platform/wop-php-sdk) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-php-sdk)](https://github.com/wop-platform/wop-php-sdk/releases)
[![CI](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/github/license/wop-platform/wop-php-sdk)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20(line%2Bbranch)-brightgreen](https://github.com/wop-platform/wop-php-sdk/actions/workflows/ci.yml) [![Gherkin](https://img.shields.io/badge/bdd-18%20scenarios-orange)](features/inbound_verification.feature) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-php-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-php-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)


Official merchant-side PHP client library for the WOP gateway: wraps the protocol core
(structured signing / content digest / L2 digital envelope / verify-and-decrypt) so merchants
can integrate securely without understanding canonicalRequest, suite derivation, or wire formats.

- Protocol source of truth: `crypto-strategy-spec.md v0.3-reviewed` (decisions D1–D13 frozen)
- Vector source of truth: `crypto-vectors.json` (verbatim copy at `tests/fixtures/`, do not edit)
- Correctness anchors: **byte-level** golden-vector assertions plus negative vectors
  (tamper / cross-family / padded base64url) that must be rejected

## Quick Start

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
    privateKey:     $merchantPrivateKeyPemOrBase64,   // own private key (outbound signing / inbound DEK unwrap)
    peerPublicKey:  $platformPublicKeyPemOrBase64,    // platform public key (verify responses / wrap DEK)
));

// 1. Build a signed request (L0 plaintext / L2 digital envelope) -> RequestDraft
$draft = $client->buildRequest('POST', '/gateway/logistics.order.query', $jsonBody, 'L2');

// 2. Send with any Transport (curl adapter / Guzzle peer adapter, or bring your own stack)
$transport = new CurlTransport();
$response  = $transport->send($draft->method, 'https://gateway.example.com' . $draft->path,
                              $this->toHeaderLines($draft->headers), $draft->wireBody);

// 3. Verify the platform response (sign -> digest -> DEK unwrap -> alg family -> decrypt, fixed order)
$result = $client->verifyResponse(
    $this->toArray($response->headers), $response->body, '/gateway/logistics.order.query');
if ($result->ok) {
    $plaintext = $result->plaintext;
}
```

`RequestDraft::headers` is an associative `name => value` array; curl needs `"$name: $value"`
lines, the Guzzle adapter accepts arrays directly — `GuzzleTransport::send()` converts internally.

## Key Preparation (D12 distribution contract)

| Purpose | Format |
|---------|--------|
| RSA public key (SPKI) | Base64 single line of X.509 SubjectPublicKeyInfo DER, or equivalent PEM (`-----BEGIN PUBLIC KEY-----`) |
| RSA private key (PKCS8) | Base64 single line of PKCS#8 DER, or equivalent PEM (`-----BEGIN PRIVATE KEY-----`) |

- Both PEM and single-line Base64 inputs are accepted equivalently (parsed and cached via phpseclib);
- Signature family: `WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` (SHA256withRSA, PKCS#1 v1.5);
- `SM2` keys (uncompressed point `04‖X‖Y`, 65B; scalar `d` 32B) belong to the SM suite, unsupported here (see roadmap).

## L0 + L2 Examples

**L0 (plaintext + digest + signature)**: `buildRequest(method, path, $body, 'L0')` —
with a body it emits `x-wop-content-digest: sha-256 <lowercase-hex>` (exactly one space);
without a body (GET) the header is absent. The digest joins
`x-wop-appkey/x-wop-nonce/x-wop-timestamp` in signedHeaders (protocol invariant I1).

**L2 (full digital envelope)**: `buildRequest(method, path, $body, 'L2')` —
generates a CSPRNG 32B DEK + 12B IV, encrypts the body with AES-256-GCM
(ciphertext = `ciphertext||tag` tail-concatenated), wraps the DEK payload
`AES-256-GCM$b64url(key)$b64url(iv)` with RSA-OAEP (**explicit dual SHA-256 + empty label**)
into `x-wop-encrypt: L2;dek=<b64url>`; the digest is computed over the **ciphertext carrier** bytes (D2).
The L2 wire body is always the JSON envelope `{"encrypted":"<base64url ciphertext>"}`
(matching the gateway CryptoFilter wire contract); on the inbound path the `encrypted`
field is extracted (unknown fields tolerated) and malformed structures / missing fields
are rejected as explicit protocol errors.

**Callback verification**: `verifyCallback($headers, $body, $callbackUrl)` — the canonical URI
is the path of the callback URL.

```php
// Merchant callback endpoint (POST)
$result = $client->verifyCallback($headers, $body, 'https://merchant.example.com/callback/notify');
```

## Vector Self-Test (conformance)

```bash
composer install
vendor/bin/phpunit                  # 139 assertions all green (golden-vector suite included)
```

- `tests/fixtures/crypto-vectors.json` is byte-identical to the gateway source (checked in CI);
- RSA signatures (3072/4096), OAEP unwrap (including the **mgf1-sha1 trap cipher that must be
  rejected**), AES-256-GCM, and digest-header assembly are all byte-level assertions;
  the `formatRules` negative vectors (double space / uppercase hex / cross-family label /
  padded base64url) are fully consumed;
- Coverage (xdebug `--path-coverage`): **lines 100.00% / branches 100.00%** (CI gate ≥98%).

## Error Handling & Obfuscation (I7)

- Configuration / parsing / format / consistency errors: throw `Wop\Sdk\WopException` with an
  explicit message (to help integration self-diagnosis);
- Signature verification and decryption failures (GCM tag / DEK unwrap): the outward message is
  **fixed** to `签名验证失败` / `解密失败` without distinguishing causes, preventing
  padding-oracle-style information leaks; callers only see `VerifyResult::reason`.

## Dependencies

| Dependency | Role |
|------------|------|
| `phpseclib/phpseclib ^3.0` | The only runtime crypto library: RSA signing + OAEP (**mandatory** — the openssl extension hard-codes OAEP MGF1 to SHA-1, violating the F2 pin) |
| `ext-openssl` (suggest) | L2 envelope AES-256-GCM bulk encryption (tag is a separate out-param; this SDK tail-concatenates) |
| `ext-curl` (suggest) | `CurlTransport` default adapter |
| `guzzlehttp/guzzle` (suggest) | `GuzzleTransport` peer adapter (kept out of core dependencies) |

## SM2-SM3 Suite Roadmap

Per SDK spec §1.2 (ruling Q7), version 0.1.0 supports **RSA suites only**; `WOP-SM2-SM3`
configuration and messages explicitly throw `WopException("SM2-SM3 套件暂未支持，见 README 路线图")`.

The planned SM support (SM3withSM2 raw r‖s 64B / SM4-GCM / SM2 C1C3C2) will ship as a pure-PHP
implementation. The golden-vector fixture is already in place (the SM sections of
`tests/fixtures/crypto-vectors.json` are currently consumed as must-reject negative tests),
so no protocol-layer changes will be needed. Feedback on priorities is welcome in issues.

## License

MIT (see [LICENSE](LICENSE)).
