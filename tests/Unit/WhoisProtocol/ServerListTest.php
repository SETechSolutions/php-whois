<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit\WhoisProtocol;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\Resources;
use SETechSolutions\Whois\WhoisProtocol\Parsing\ParserFactory;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldParser;
use SETechSolutions\Whois\WhoisProtocol\Server;
use SETechSolutions\Whois\WhoisProtocol\ServerList;

class ServerListTest extends TestCase
{
    private static function server(string $zone, string $host = 'some.host.net'): Server
    {
        return new Server($zone, $host, false, ParserFactory::create());
    }

    /**
     * @param string[] $zones
     * @return string[] Zones of the servers matching the domain, in match order
     */
    private static function matchedZones(array $zones, string $domain): array
    {
        $list = new ServerList(array_map(function ($zone) {
            return self::server($zone);
        }, $zones));
        return array_map(function (Server $server) {
            return $server->zone();
        }, $list->match($domain));
    }

    public function testEmptyListMatchesNothing()
    {
        $this->assertSame([], (new ServerList())->match('domain.com'));
    }

    public function testMatchesEveryServerOfTheZone()
    {
        $zones = ['.net', '.com', '.net', '.com', '.su', '.com', '.gov'];

        $this->assertSame(['.com', '.com', '.com'], self::matchedZones($zones, 'domain.com'));
        $this->assertSame([], self::matchedZones($zones, 'domain.xyz'));
    }

    public function testServersOfOneZoneKeepTheirOrder()
    {
        $list = new ServerList([self::server('.com', 'first'), self::server('.net', 'x'), self::server('.com', 'second')]);
        $hosts = array_map(function (Server $server) {
            return $server->host();
        }, $list->match('domain.com'));

        $this->assertSame(['first', 'second'], $hosts);
    }

    public function testMostSpecificZoneComesFirst()
    {
        $zones = ['.com', '.bar.com', '.foo.bar.com'];

        $this->assertSame(['.foo.bar.com', '.bar.com', '.com'], self::matchedZones($zones, 'domain.foo.bar.com'));
        $this->assertSame(['.bar.com', '.com'], self::matchedZones($zones, 'domain.bar.com'));
        $this->assertSame(['.com'], self::matchedZones($zones, 'domain.com'));
        $this->assertSame(['.bar.com', '.com'], self::matchedZones(['.com', '.bar.com'], 'domain.foo.bar.com'));
    }

    public function testWildcardZones()
    {
        $this->assertSame(['.com'], self::matchedZones(['.com', '.*.com'], 'domain.com'));
        $this->assertSame(
            ['.foo.*.*', '.bar.com', '.bar.*', '.*.com', '.*'],
            self::matchedZones(['.*', '.*.foo', '.*.com', '.bar.*', '.foo.*.*', '.bar.com'], 'domain.foo.bar.com')
        );
    }

    public function testRootZoneMatchesSingleLabels()
    {
        $this->assertSame(['.'], self::matchedZones(['.', '.com'], 'com'));
        $this->assertSame(['.com'], self::matchedZones(['.', '.com'], 'domain.com'));
    }

    public function testServerNormalizesZoneAndBuildsQueries()
    {
        $server = self::server('com', 'whois.host');

        $this->assertSame('.com', $server->zone());
        $this->assertSame('whois.host', $server->host());
        $this->assertFalse($server->isCentralized());
        $this->assertSame("domain.com\r\n", $server->buildQuery('domain.com'));
        $this->assertSame("=domain.com\r\n", $server->buildQuery('domain.com', true));

        $custom = new Server('.de', 'whois.denic.de', true, ParserFactory::create(), "-T dn %s\r\n");
        $this->assertTrue($custom->isCentralized());
        $this->assertSame("-T dn domain.de\r\n", $custom->buildQuery('domain.de'));
    }

    public function testServerNeedsZoneAndHost()
    {
        try {
            self::server('', 'host');
            $this->fail('An empty zone was accepted');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('Zone', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        self::server('.com', '');
    }

    public function testServerFromConfig()
    {
        $server = Server::fromConfig([
            'zone' => '.abc',
            'host' => 'some.host',
            'centralized' => true,
            'parserType' => TldParser::BLOCK,
            'queryFormat' => "prefix %s suffix\r\n",
        ]);

        $this->assertSame('.abc', $server->zone());
        $this->assertTrue($server->isCentralized());
        $this->assertSame(TldParser::BLOCK, $server->parser()->getType());
        $this->assertSame("prefix domain.abc suffix\r\n", $server->buildQuery('domain.abc'));

        $this->assertSame(TldParser::AUTO, Server::fromConfig(['zone' => '.abc', 'host' => 'h'])->parser()->getType());
    }

    public function testBundledListAndExtraServers()
    {
        $bundled = ServerList::bundled();
        $this->assertGreaterThan(1000, count($bundled->all()));
        $this->assertNotEmpty($bundled->match('google.com'));
        $this->assertSame([], $bundled->match('google.example-unknown'));

        $withExtra = ServerList::bundled([['zone' => '.com', 'host' => 'whois.mine.example']]);
        $this->assertSame('whois.mine.example', $withExtra->match('google.com')[0]->host());
    }

    /**
     * A subzone entry that repeats the host of its top-level zone adds nothing.
     */
    public function testBundledListHasNoUnnecessarySubzones()
    {
        $data = Resources::load('whois-servers');
        $hostsOfTld = [];
        foreach ($data as $row) {
            if (preg_match('~^\.\w+$~', $row['zone'])) {
                $hostsOfTld[$row['zone']][] = $row['host'];
            }
        }
        $found = [];
        foreach ($data as $row) {
            if (preg_match('~^.+?(\.\w+)$~', $row['zone'], $m) && in_array($row['host'], $hostsOfTld[$m[1]] ?? [], true)) {
                $found[] = "{$row['zone']} repeats {$row['host']}";
            }
        }
        $this->assertSame([], $found);
    }
}
