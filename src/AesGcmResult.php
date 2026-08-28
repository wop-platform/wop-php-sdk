<?php

declare(strict_types=1);

namespace Wop\Sdk;

/**
 * AES-GCM 加密结果：cipherTag（ciphertext||tag）与 IV 同生同传。
 */
final class AesGcmResult
{
    public function __construct(
        public readonly string $cipherTag,
        public readonly string $iv,
    ) {
    }
}
