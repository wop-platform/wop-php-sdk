<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * AES-GCM 加密结果：cipherTag（ciphertext||tag）与 IV 同生同传。
 */
final class AesGcmResult
{
    /**
     * @param string $cipherTag ciphertext||tag 尾拼密文（线上形态）
     * @param string $iv 12 字节 IV（与密文同生同传）
     */
    public function __construct(
        public readonly string $cipherTag,
        public readonly string $iv,
    ) {
    }
}
