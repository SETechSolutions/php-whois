<?php

declare(strict_types=1);

namespace Iodev\Whois\Compat;

use PHPUnit\Framework\TestCase;

/**
 * This package is a drop-in replacement for io-developer/php-whois 4.1.10,
 * so nothing from that version's public or protected API may be removed or changed.
 */
class ApiCompatibilityTest extends TestCase
{
    public function testApiOf4110IsKept()
    {
        $baseline = json_decode(file_get_contents(__DIR__ . '/api-4.1.10.json'), true);
        $current = ApiSnapshot::build(__DIR__ . '/../../../../src/Iodev/Whois');

        self::assertSame([], ApiSnapshot::findBreaks($baseline, $current));
    }
}
