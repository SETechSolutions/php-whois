<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit\Rdap;

use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\Rdap\Bootstrap;
use SETechSolutions\Whois\Tests\Fakes\FakeHttpClient;

class BootstrapTest extends TestCase
{
    public function testFromIanaData()
    {
        $bootstrap = Bootstrap::fromIanaData([
            'services' => [
                [['com', 'net'], ['https://rdap.verisign.example/']],
                [['org'], ['http://rdap.org.example/', 'https://rdap.org.example/']],
            ],
        ]);

        $this->assertSame(['https://rdap.verisign.example/'], $bootstrap->match('google.com'));
        $this->assertSame(['https://rdap.verisign.example/'], $bootstrap->match('sub.google.NET'));
        // HTTPS first
        $this->assertSame(['https://rdap.org.example/', 'http://rdap.org.example/'], $bootstrap->match('wikipedia.org'));
        $this->assertSame([], $bootstrap->match('google.de'));
    }

    public function testMostSpecificZoneWins()
    {
        $bootstrap = new Bootstrap([
            'uk' => 'https://uk.example/',
            'co.uk' => 'https://co-uk.example/',
        ]);

        $this->assertSame(['https://co-uk.example/'], $bootstrap->match('bbc.co.uk'));
        $this->assertSame(['https://uk.example/'], $bootstrap->match('example.uk'));
        // A zone never matches itself
        $this->assertSame(['https://uk.example/'], $bootstrap->match('co.uk'));
        $this->assertSame([], $bootstrap->match('uk'));
    }

    public function testAddServersReplacesZone()
    {
        $bootstrap = new Bootstrap(['com' => 'https://old.example/']);
        $bootstrap->addServers(['.COM' => ['https://new.example/']]);

        $this->assertSame(['https://new.example/'], $bootstrap->match('google.com'));
    }

    public function testBundledSnapshot()
    {
        $bootstrap = Bootstrap::bundled();

        $this->assertSame(['https://rdap.verisign.com/com/v1/'], $bootstrap->match('google.com'));
        $this->assertGreaterThan(1000, count($bootstrap->servers()));
    }

    public function testFromIana()
    {
        $http = new FakeHttpClient([
            Bootstrap::IANA_DNS_URL => ['status' => 200, 'body' => json_encode(['services' => [[['test'], ['https://rdap.test/']]]])],
        ]);

        $this->assertSame(['https://rdap.test/'], Bootstrap::fromIana($http)->match('example.test'));
    }

    public function testFromIanaFailure()
    {
        $this->expectException(WhoisException::class);
        Bootstrap::fromIana(new FakeHttpClient());
    }
}
