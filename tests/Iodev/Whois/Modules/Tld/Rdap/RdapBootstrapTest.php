<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Rdap;

use Iodev\Whois\Factory;
use Iodev\Whois\Loaders\FakeHttpLoader;
use Iodev\Whois\Exceptions\WhoisException;
use PHPUnit\Framework\TestCase;

class RdapBootstrapTest extends TestCase
{
    public function testFromIanaData()
    {
        $b = RdapBootstrap::fromIanaData([
            'services' => [
                [['com', 'net'], ['https://rdap.verisign.example/']],
                [['org'], ['http://rdap.org.example/', 'https://rdap.org.example/']],
            ],
        ]);

        self::assertSame(['https://rdap.verisign.example/'], $b->matchUrls('google.com'));
        self::assertSame(['https://rdap.verisign.example/'], $b->matchUrls('sub.google.NET'));
        // HTTPS first
        self::assertSame(['https://rdap.org.example/', 'http://rdap.org.example/'], $b->matchUrls('wikipedia.org'));
        self::assertSame([], $b->matchUrls('google.de'));
    }

    public function testMostSpecificZoneWins()
    {
        $b = new RdapBootstrap([
            'uk' => 'https://uk.example/',
            'co.uk' => 'https://co-uk.example/',
        ]);

        self::assertSame(['https://co-uk.example/'], $b->matchUrls('bbc.co.uk'));
        self::assertSame(['https://uk.example/'], $b->matchUrls('example.uk'));
        // A zone never matches itself
        self::assertSame(['https://uk.example/'], $b->matchUrls('co.uk'));
        self::assertSame([], $b->matchUrls('uk'));
    }

    public function testAddServersReplacesZone()
    {
        $b = new RdapBootstrap(['com' => 'https://old.example/']);
        $b->addServers(['.COM' => ['https://new.example/']]);

        self::assertSame(['https://new.example/'], $b->matchUrls('google.com'));
    }

    public function testUnicodeDomainMatchesPunycodeZone()
    {
        $b = new RdapBootstrap(['xn--p1ai' => 'https://rf.example/']);

        self::assertSame(['https://rf.example/'], $b->matchUrls('пример.рф'));
    }

    public function testBundledSnapshot()
    {
        $b = Factory::get()->createRdapBootstrap();

        self::assertSame(['https://rdap.verisign.com/com/v1/'], $b->matchUrls('google.com'));
        self::assertGreaterThan(1000, count($b->getServers()));
    }

    public function testLoadFromIana()
    {
        $l = new FakeHttpLoader();
        $l->responses[RdapBootstrap::IANA_DNS_URL] = [
            'status' => 200,
            'body' => json_encode(['services' => [[['test'], ['https://rdap.test/']]]]),
        ];

        $b = RdapBootstrap::loadFromIana($l);

        self::assertSame(['https://rdap.test/'], $b->matchUrls('example.test'));
    }

    public function testLoadFromIanaFailure()
    {
        $this->expectException(WhoisException::class);
        RdapBootstrap::loadFromIana(new FakeHttpLoader());
    }
}
