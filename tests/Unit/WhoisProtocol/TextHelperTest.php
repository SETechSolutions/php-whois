<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit\WhoisProtocol;

use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TextHelper;

class TextHelperTest extends TestCase
{
    private static function fixture(string $name): string
    {
        return file_get_contents(__DIR__ . '/../../fixtures/text/' . $name);
    }

    /**
     * The recorded files differ in line endings, which is not what is being tested.
     */
    private static function sameLineEndings(string $text): string
    {
        return preg_replace('~\r\n|\r~', "\n", $text);
    }

    public function testLatin1BecomesUtf8()
    {
        $this->assertSame(
            self::sameLineEndings(self::fixture('encoding.fin.out.txt')),
            self::sameLineEndings(TextHelper::toUtf8(self::fixture('encoding.fin.in.txt')))
        );
    }

    public function testWindows1251BecomesUtf8()
    {
        $this->assertSame(
            self::sameLineEndings(self::fixture('encoding.ukr.out.txt')),
            self::sameLineEndings(TextHelper::toUtf8(self::fixture('encoding.ukr.in.txt')))
        );
    }

    public function testUtf8StaysAsItIs()
    {
        $this->assertSame('Sisäministeriö пример', TextHelper::toUtf8('Sisäministeriö пример'));
    }
}
