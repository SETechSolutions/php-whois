<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Live;

use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\Mode;
use SETechSolutions\Whois\Whois;

/**
 * Queries real servers, so it can fail when a registry changes something or rate-limits.
 * Not part of the default run: composer test-live
 */
class LiveLookupTest extends TestCase
{
    public function testComOverRdap()
    {
        $info = (new Whois())->lookup('google.com');

        $this->assertSame('rdap', $info->source());
        $this->assertSame('google.com', $info->domain());
        $this->assertStringContainsStringIgnoringCase('markmonitor', $info->registrar());
        $this->assertGreaterThan(time(), $info->expiresAt()->getTimestamp());
        $this->assertContains('ns1.google.com', $info->nameServers());
    }

    public function testUnregisteredComIsAvailable()
    {
        $this->assertTrue((new Whois())->isAvailable('php-whois-' . bin2hex(random_bytes(6)) . '.com'));
    }

    public function testZoneWithoutRdapFallsBackToWhois()
    {
        // .de has no RDAP server in IANA's bootstrap file
        $info = (new Whois())->lookup('denic.de');

        $this->assertNotNull($info);
        $this->assertSame('whois', $info->source());
        $this->assertSame('denic.de', $info->domain());
    }

    public function testInternationalDomain()
    {
        $info = (new Whois())->lookup('münchen.de');

        $this->assertSame('xn--mnchen-3ya.de', $info->domain());
        $this->assertSame('münchen.de', $info->unicodeDomain());
    }

    public function testRawIsWhoisText()
    {
        $raw = (new Whois())->raw('google.com');

        $this->assertSame('whois', $raw->source());
        $this->assertStringContainsStringIgnoringCase('domain name: google.com', $raw->text());
    }

    public function testWhoisOnlyAndRdapOnly()
    {
        $this->assertSame('whois', (new Whois(['mode' => Mode::WHOIS_ONLY]))->lookup('google.com')->source());
        $this->assertSame('rdap', (new Whois(['mode' => Mode::RDAP_ONLY]))->lookup('wikipedia.org')->source());
    }

    public function testThroughCurl()
    {
        // Any curl option switches WHOIS queries to curl as well
        $whois = new Whois(['mode' => Mode::WHOIS_ONLY, 'curl_options' => [CURLOPT_TCP_NODELAY => true]]);

        $this->assertSame('denic.de', $whois->lookup('denic.de')->domain());
    }
}
