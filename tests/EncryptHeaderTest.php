<?php

declare(strict_types=1);

namespace Wop\Sdk\Tests;

use PHPUnit\Framework\TestCase;
use Wop\Sdk\EncryptHeader;
use Wop\Sdk\WopException;

/** x-wop-encrypt 指令：L0/L2;dek=<base64url>。 */
final class EncryptHeaderTest extends TestCase
{
    public function testParseNullIsL0(): void
    {
        $parsed = EncryptHeader::parse(null);
        $this->assertSame('L0', $parsed->level);
        $this->assertNull($parsed->dek);
        $this->assertFalse($parsed->isEncrypted());

        $blank = EncryptHeader::parse('  ');
        $this->assertSame('L0', $blank->level);
    }

    public function testParseL2WithDek(): void
    {
        $parsed = EncryptHeader::parse('L2;dek=AbC-123');
        $this->assertSame('L2', $parsed->level);
        $this->assertSame('AbC-123', $parsed->dek);
        $this->assertTrue($parsed->isEncrypted());
    }

    public function testParseLowercaseLevel(): void
    {
        $this->assertTrue(EncryptHeader::parse('l2;dek=x')->isEncrypted());
        $this->assertFalse(EncryptHeader::parse('l0')->isEncrypted());
    }

    public function testParseRejectsUnknownLevel(): void
    {
        $this->expectException(WopException::class);
        $this->expectExceptionMessage('L0/L2');
        EncryptHeader::parse('L1');
    }

    public function testBuild(): void
    {
        $this->assertSame('L2;dek=xyz', EncryptHeader::build('L2', 'xyz'));
        $this->assertSame('L0', EncryptHeader::build('L0', null));
    }


    public function testParseL2WithoutDek(): void
    {
        $parsed = EncryptHeader::parse('L2');
        $this->assertTrue($parsed->isEncrypted());
        $this->assertNull($parsed->dek);
    }

    public function testParseTolerantWhitespaceAroundParts(): void
    {
        $parsed = EncryptHeader::parse(' L2 ; dek=xyz ');
        $this->assertSame('L2', $parsed->level);
        $this->assertSame('xyz', $parsed->dek);
        // 'dek ='（键名内空格）不识别 → 视为无 dek 指令
        $this->assertNull(EncryptHeader::parse('L2; dek = xyz')->dek);
    }
}
