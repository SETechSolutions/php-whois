<?php

declare(strict_types=1);

namespace Iodev\Whois\Live;

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\LookupMode;
use Iodev\Whois\Modules\Tld\TldResponse;
use Iodev\Whois\Whois;
use PHPUnit\Framework\TestCase;

/**
 * Queries real servers, so it can fail when a registry changes or rate-limits.
 * Excluded from the default run; use: composer test-live
 *
 * @group live
 */
class LiveLookupTest extends TestCase
{
    /**
     * @return Whois
     */
    private static function whois()
    {
        return Factory::get()->createWhois();
    }

    public function testComOverRdap()
    {
        $info = self::whois()->loadDomainInfo('google.com');

        self::assertSame('rdap', $info->parserType);
        self::assertSame('google.com', $info->domainName);
        self::assertStringContainsStringIgnoringCase('markmonitor', $info->registrar);
        self::assertGreaterThan(time(), $info->expirationDate);
        self::assertContains('ns1.google.com', $info->nameServers);
    }

    public function testUnregisteredComIsAvailable()
    {
        self::assertTrue(self::whois()->isDomainAvailable('php-whois-' . bin2hex(random_bytes(6)) . '.com'));
    }

    public function testZoneWithoutRdapFallsBackToWhois()
    {
        // .de has no RDAP server in IANA's bootstrap file
        $info = self::whois()->loadDomainInfo('denic.de');

        self::assertNotNull($info);
        self::assertSame(TldResponse::SOURCE_WHOIS, $info->getResponse()->getSource());
    }

    public function testLookupDomainReturnsWhoisText()
    {
        $response = self::whois()->lookupDomain('google.com');

        self::assertSame(TldResponse::SOURCE_WHOIS, $response->getSource());
        self::assertStringContainsStringIgnoringCase('domain name: google.com', $response->text);
    }

    public function testRdapOnly()
    {
        $whois = self::whois()->setLookupMode(LookupMode::RDAP_ONLY);

        self::assertSame('rdap', $whois->loadDomainInfo('wikipedia.org')->parserType);
    }
}
