<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit\Rdap;

use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\Rdap\RdapParser;

class RdapParserTest extends TestCase
{
    private static function parseFile(string $domain, string $file): array
    {
        return (new RdapParser())->parse(file_get_contents(__DIR__ . '/../../fixtures/rdap/' . $file), $domain);
    }

    private static function parseDomainObject(array $entities = [], array $extra = []): array
    {
        return (new RdapParser())->parse(json_encode(array_merge([
            'objectClassName' => 'domain',
            'ldhName' => 'EXAMPLE.TEST',
            'status' => ['active'],
            'entities' => $entities,
        ], $extra)), 'example.test');
    }

    public function testComRegistryResponse()
    {
        $data = self::parseFile('google.com', 'google.com.json');

        $this->assertSame('google.com', $data['domain']);
        $this->assertSame('', $data['whoisServer']);
        $this->assertSame(['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'], $data['nameServers']);
        $this->assertSame('unsigned', $data['dnssec']);
        $this->assertSame(strtotime('1997-09-15T04:00:00Z'), $data['createdAt']);
        $this->assertSame(strtotime('2028-09-14T04:00:00Z'), $data['expiresAt']);
        $this->assertSame(strtotime('2019-09-09T15:39:04Z'), $data['updatedAt']);
        $this->assertSame([
            'clientdeleteprohibited',
            'clienttransferprohibited',
            'clientupdateprohibited',
            'serverdeleteprohibited',
            'servertransferprohibited',
            'serverupdateprohibited',
        ], $data['statuses']);
        $this->assertSame('', $data['owner']);
        $this->assertSame('MarkMonitor Inc.', $data['registrar']);
        $this->assertSame('https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM', $data['relatedUrl']);
    }

    public function testRegistrarResponse()
    {
        $data = self::parseFile('google.com', 'google.com_registrar.json');

        $this->assertSame('whois.markmonitor.com', $data['whoisServer']);
        // The registrant's fn is "REDACTED REGISTRANT" but the org is public
        $this->assertSame('Google LLC', $data['owner']);
        $this->assertSame('Markmonitor Inc.', $data['registrar']);
        // "expiration", not "registrar expiration"
        $this->assertSame(strtotime('2028-09-13T07:00:00Z'), $data['expiresAt']);
        $this->assertSame('', $data['relatedUrl']);
    }

    public function testOrgResponse()
    {
        $data = self::parseFile('wikipedia.org', 'wikipedia.org.json');

        $this->assertSame('wikipedia.org', $data['domain']);
        $this->assertSame(['ns0.wikimedia.org', 'ns1.wikimedia.org', 'ns2.wikimedia.org'], $data['nameServers']);
        $this->assertSame(strtotime('2001-01-13T00:12:14Z'), $data['createdAt']);
        $this->assertSame(strtotime('2027-01-13T00:12:14Z'), $data['expiresAt']);
    }

    public function testUkResponseTrimsNameServerDotsAndSkipsRedactedOwner()
    {
        $data = self::parseFile('bbc.co.uk', 'bbc.co.uk.json');

        $this->assertSame('bbc.co.uk', $data['domain']);
        $this->assertContains('dns0.bbc.co.uk', $data['nameServers']);
        $this->assertNotContains('dns0.bbc.co.uk.', $data['nameServers']);
        $this->assertSame('', $data['owner']);
        $this->assertSame('British Broadcasting Corporation', $data['registrar']);
    }

    public function testActiveStatusBecomesOk()
    {
        $this->assertSame(['ok'], self::parseDomainObject()['statuses']);
    }

    public function testRedactedOwnerIsEmpty()
    {
        $data = self::parseDomainObject([[
            'roles' => ['registrant'],
            'vcardArray' => ['vcard', [['version', [], 'text', '4.0'], ['org', [], 'text', 'REDACTED FOR PRIVACY'], ['fn', [], 'text', 'Data Redacted']]],
        ]]);

        $this->assertSame('', $data['owner']);
    }

    public function testDnssec()
    {
        $this->assertSame('signedDelegation', self::parseDomainObject([], ['secureDNS' => ['delegationSigned' => true]])['dnssec']);
        $this->assertSame('unsigned', self::parseDomainObject([], ['secureDNS' => ['delegationSigned' => false]])['dnssec']);
        $this->assertSame('', self::parseDomainObject()['dnssec']);
    }

    public function testMissingDatesAreZero()
    {
        $data = self::parseDomainObject();

        $this->assertSame(0, $data['createdAt']);
        $this->assertSame(0, $data['expiresAt']);
    }

    public function testAnythingButADomainObjectIsNull()
    {
        $parser = new RdapParser();

        $this->assertNull($parser->parse(json_encode(['errorCode' => 404, 'title' => 'Not Found']), 'example.test'));
        $this->assertNull($parser->parse('not json', 'example.test'));
        $this->assertNull($parser->parse('', 'example.test'));
    }
}
