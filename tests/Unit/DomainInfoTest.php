<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\DomainInfo;
use SETechSolutions\Whois\RawResponse;

class DomainInfoTest extends TestCase
{
    private static function info(array $data = []): DomainInfo
    {
        return new DomainInfo(array_replace([
            'domain' => 'xn--mnchen-3ya.de',
            'registrar' => 'Example Registrar',
            'owner' => 'Example Org',
            'createdAt' => strtotime('2001-02-03T04:05:06Z'),
            'updatedAt' => 0,
            'expiresAt' => strtotime('2031-02-03T04:05:06Z'),
            'nameServers' => ['ns1.example.net', 'ns2.example.net'],
            'statuses' => ['ok'],
            'dnssec' => 'unsigned',
            'whoisServer' => 'whois.example.net',
        ], $data), new RawResponse('{"raw":true}', RawResponse::SOURCE_RDAP, 'rdap.example.net', 'https://rdap.example.net/domain/x'));
    }

    public function testFields()
    {
        $info = self::info();

        $this->assertSame('xn--mnchen-3ya.de', $info->domain());
        $this->assertSame('münchen.de', $info->unicodeDomain());
        $this->assertSame('Example Registrar', $info->registrar());
        $this->assertSame('Example Org', $info->owner());
        $this->assertSame(['ns1.example.net', 'ns2.example.net'], $info->nameServers());
        $this->assertSame(['ok'], $info->statuses());
        $this->assertSame('unsigned', $info->dnssec());
        $this->assertSame('whois.example.net', $info->whoisServer());
        $this->assertSame('rdap', $info->source());
    }

    public function testDatesAreUtcObjectsOrNull()
    {
        $info = self::info();

        $this->assertInstanceOf(DateTimeImmutable::class, $info->createdAt());
        $this->assertSame('2001-02-03T04:05:06+00:00', $info->createdAt()->format(DATE_ATOM));
        $this->assertSame('2031-02-03T04:05:06+00:00', $info->expiresAt()->format(DATE_ATOM));
        $this->assertNull($info->updatedAt());
    }

    public function testRawResponse()
    {
        $raw = self::info()->raw();

        $this->assertSame('{"raw":true}', $raw->text());
        $this->assertSame('{"raw":true}', (string)$raw);
        $this->assertSame('rdap', $raw->source());
        $this->assertSame('rdap.example.net', $raw->server());
        $this->assertSame('https://rdap.example.net/domain/x', $raw->query());
    }

    public function testMissingFieldsAreEmpty()
    {
        $info = new DomainInfo(['domain' => 'example.com'], new RawResponse('', RawResponse::SOURCE_WHOIS, 'whois.example'));

        $this->assertSame('', $info->registrar());
        $this->assertSame('', $info->owner());
        $this->assertSame([], $info->nameServers());
        $this->assertSame([], $info->statuses());
        $this->assertNull($info->createdAt());
        $this->assertNull($info->expiresAt());
        $this->assertSame('whois', $info->source());
    }

    public function testToArrayAndJson()
    {
        $expected = [
            'domain' => 'xn--mnchen-3ya.de',
            'registrar' => 'Example Registrar',
            'owner' => 'Example Org',
            'createdAt' => '2001-02-03T04:05:06+00:00',
            'updatedAt' => null,
            'expiresAt' => '2031-02-03T04:05:06+00:00',
            'nameServers' => ['ns1.example.net', 'ns2.example.net'],
            'statuses' => ['ok'],
            'dnssec' => 'unsigned',
            'whoisServer' => 'whois.example.net',
            'source' => 'rdap',
        ];

        $this->assertSame($expected, self::info()->toArray());
        $this->assertSame($expected, json_decode(json_encode(self::info()), true));
    }
}
