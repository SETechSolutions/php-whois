<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Modules\Tld\TldResponse;
use PHPUnit\Framework\TestCase;

class RdapParserTest extends TestCase
{
    /**
     * @param string $domain
     * @param string $text
     * @return \Iodev\Whois\Modules\Tld\TldInfo|null
     */
    private static function parse($domain, $text)
    {
        $parser = Factory::get()->createTldParser(TldParser::RDAP);
        return $parser->parseResponse(new TldResponse([
            'domain' => $domain,
            'host' => 'rdap.example',
            'query' => "https://rdap.example/domain/$domain",
            'text' => $text,
            'source' => TldResponse::SOURCE_RDAP,
            'httpStatus' => 200,
        ]));
    }

    /**
     * @param string $domain
     * @param string $filename
     * @return \Iodev\Whois\Modules\Tld\TldInfo|null
     */
    private static function parseFile($domain, $filename)
    {
        return self::parse($domain, file_get_contents(__DIR__ . '/../rdap_data/' . $filename));
    }

    /**
     * @param array $vcard
     * @param array $extra
     * @return string
     */
    private static function domainJson(array $entities, array $extra = [])
    {
        return json_encode(array_merge([
            'objectClassName' => 'domain',
            'ldhName' => 'EXAMPLE.TEST',
            'status' => ['active'],
            'entities' => $entities,
        ], $extra));
    }

    public function testFactoryCreatesRdapParser()
    {
        $parser = Factory::get()->createTldParser(TldParser::RDAP);
        self::assertInstanceOf(RdapParser::class, $parser);
        self::assertSame(TldParser::RDAP, $parser->getType());
    }

    public function testComRegistryResponse()
    {
        $info = self::parseFile('google.com', 'google.com.json');

        self::assertNotNull($info);
        self::assertSame('rdap', $info->parserType);
        self::assertSame('google.com', $info->domainName);
        self::assertSame('', $info->whoisServer);
        self::assertSame(['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'], $info->nameServers);
        self::assertSame('unsigned', $info->dnssec);
        self::assertSame(strtotime('1997-09-15T04:00:00Z'), $info->creationDate);
        self::assertSame(strtotime('2028-09-14T04:00:00Z'), $info->expirationDate);
        self::assertSame(strtotime('2019-09-09T15:39:04Z'), $info->updatedDate);
        self::assertSame([
            'clientdeleteprohibited',
            'clienttransferprohibited',
            'clientupdateprohibited',
            'serverdeleteprohibited',
            'servertransferprohibited',
            'serverupdateprohibited',
        ], $info->states);
        self::assertSame('', $info->owner);
        self::assertSame('MarkMonitor Inc.', $info->registrar);
        self::assertSame('GOOGLE.COM', $info->getExtraVal('rdap')['ldhName']);
    }

    public function testRegistrarResponse()
    {
        $info = self::parseFile('google.com', 'google.com_registrar.json');

        self::assertSame('whois.markmonitor.com', $info->whoisServer);
        // The registrant's fn is "REDACTED REGISTRANT" but the org is public
        self::assertSame('Google LLC', $info->owner);
        self::assertSame('Markmonitor Inc.', $info->registrar);
        // "expiration", not "registrar expiration"
        self::assertSame(strtotime('2028-09-13T07:00:00Z'), $info->expirationDate);
    }

    public function testOrgResponse()
    {
        $info = self::parseFile('wikipedia.org', 'wikipedia.org.json');

        self::assertSame('wikipedia.org', $info->domainName);
        self::assertSame(['ns0.wikimedia.org', 'ns1.wikimedia.org', 'ns2.wikimedia.org'], $info->nameServers);
        self::assertSame(strtotime('2001-01-13T00:12:14Z'), $info->creationDate);
        self::assertSame(strtotime('2027-01-13T00:12:14Z'), $info->expirationDate);
    }

    public function testUkResponseTrimsNameServerDotsAndSkipsRedactedOwner()
    {
        $info = self::parseFile('bbc.co.uk', 'bbc.co.uk.json');

        self::assertSame('bbc.co.uk', $info->domainName);
        self::assertContains('dns0.bbc.co.uk', $info->nameServers);
        self::assertNotContains('dns0.bbc.co.uk.', $info->nameServers);
        self::assertSame('', $info->owner);
        self::assertSame('British Broadcasting Corporation', $info->registrar);
    }

    public function testActiveStatusBecomesOk()
    {
        $info = self::parse('example.test', self::domainJson([]));

        self::assertSame(['ok'], $info->states);
    }

    public function testRedactedOwnerIsEmpty()
    {
        $info = self::parse('example.test', self::domainJson([[
            'roles' => ['registrant'],
            'vcardArray' => ['vcard', [['version', [], 'text', '4.0'], ['org', [], 'text', 'REDACTED FOR PRIVACY'], ['fn', [], 'text', 'Data Redacted']]],
        ]]));

        self::assertSame('', $info->owner);
    }

    public function testSignedDelegation()
    {
        $info = self::parse('example.test', self::domainJson([], ['secureDNS' => ['delegationSigned' => true]]));

        self::assertSame('signedDelegation', $info->dnssec);
    }

    public function testMissingSecureDnsGivesEmptyDnssec()
    {
        $info = self::parse('example.test', self::domainJson([]));

        self::assertSame('', $info->dnssec);
    }

    public function testNonDomainObjectIsNull()
    {
        self::assertNull(self::parse('example.test', json_encode(['errorCode' => 404, 'title' => 'Not Found'])));
        self::assertNull(self::parse('example.test', 'not json'));
    }

    public function testInfoIsJsonSerializable()
    {
        $info = self::parseFile('google.com', 'google.com.json');
        $json = json_decode(json_encode($info), true);

        self::assertSame('google.com', $json['domainName']);
        self::assertSame('rdap', $json['parserType']);
    }
}
