<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol;

use SETechSolutions\Whois\Resources;
use SETechSolutions\Whois\WhoisProtocol\Parsing\ParserFactory;

/**
 * The known WHOIS servers, ordered so the most specific zone comes first.
 *
 * @internal
 */
class ServerList
{
    /** @var Server[] */
    private $servers = [];

    /**
     * The list shipped in resources/whois-servers.json, with extra entries ahead of it:
     * for a zone both name, the extra entry is tried first.
     *
     * @param array $extraConfigs Server entries, each ['zone' => '.x', 'host' => '...', ...]
     */
    public static function bundled(array $extraConfigs = []): self
    {
        $defaultParser = ParserFactory::create();
        $servers = [];
        foreach (array_merge(array_values($extraConfigs), Resources::load('whois-servers')) as $config) {
            $servers[] = Server::fromConfig((array)$config, $defaultParser);
        }
        return new self($servers);
    }

    /**
     * @param Server[] $servers In priority order for servers of the same zone
     */
    public function __construct(array $servers = [])
    {
        $weights = [];
        foreach (array_values($servers) as $index => $server) {
            $parts = explode('.', $server->zone());
            $rootZone = array_pop($parts);
            $subZone1 = $parts ? array_pop($parts) : '';
            $subZone2 = $parts ? array_pop($parts) : '';
            $weights[] = [
                sprintf('%16s.%16s.%32s.%13s', $subZone2, $subZone1, $rootZone, 1000000 - $index),
                $server,
            ];
        }
        usort($weights, function (array $a, array $b) {
            return strcmp($b[0], $a[0]);
        });
        $this->servers = array_column($weights, 1);
    }

    /**
     * @return Server[]
     */
    public function all(): array
    {
        return $this->servers;
    }

    /**
     * @return Server[] Servers whose zone matches the domain, most specific first
     */
    public function match(string $asciiDomain): array
    {
        $matched = [];
        foreach ($this->servers as $server) {
            if ($server->matchDomain($asciiDomain) > 0) {
                $matched[] = $server;
            }
        }
        return $matched;
    }
}
