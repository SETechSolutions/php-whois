<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol;

use InvalidArgumentException;
use SETechSolutions\Whois\WhoisProtocol\Parsing\ParserFactory;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldParser;

/**
 * A WHOIS server for one zone, with the parser its replies need.
 *
 * @internal
 */
class Server
{
    /** @var string */
    private $zone;

    /** @var string[] */
    private $inverseZoneParts;

    /** @var string */
    private $host;

    /** @var bool */
    private $centralized;

    /** @var TldParser */
    private $parser;

    /** @var string */
    private $queryFormat;

    /**
     * @param array $config Keys: zone, host; optional centralized, queryFormat, parserType, parserOptions, parserClass
     */
    public static function fromConfig(array $config, ?TldParser $defaultParser = null): self
    {
        return new self(
            (string)($config['zone'] ?? ''),
            (string)($config['host'] ?? ''),
            !empty($config['centralized']),
            ParserFactory::forServerConfig($config, $defaultParser),
            $config['queryFormat'] ?? null
        );
    }

    /**
     * @param string $zone E.g. ".com", ".co.uk", ".*.net"
     * @param string $host
     * @param bool $centralized True when the server's answer is final and names no further server to ask
     * @param TldParser $parser
     * @param string|null $queryFormat sprintf format of the query line, "%s\r\n" by default
     */
    public function __construct(string $zone, string $host, bool $centralized, TldParser $parser, $queryFormat = null)
    {
        if ($zone === '') {
            throw new InvalidArgumentException('Zone must be specified');
        }
        if ($host === '') {
            throw new InvalidArgumentException('Host must be specified');
        }
        $this->zone = ($zone[0] === '.') ? $zone : ".$zone";
        $this->inverseZoneParts = array_reverse(explode('.', $this->zone));
        array_pop($this->inverseZoneParts);
        $this->host = $host;
        $this->centralized = $centralized;
        $this->parser = $parser;
        $this->queryFormat = !empty($queryFormat) ? (string)$queryFormat : "%s\r\n";
    }

    public function zone(): string
    {
        return $this->zone;
    }

    public function host(): string
    {
        return $this->host;
    }

    public function isCentralized(): bool
    {
        return $this->centralized;
    }

    public function parser(): TldParser
    {
        return $this->parser;
    }

    /**
     * @return int How many labels of the zone matched, 0 for no match
     */
    public function matchDomain(string $asciiDomain): int
    {
        $domainParts = explode('.', $asciiDomain);
        if ($this->zone === '.' && count($domainParts) === 1) {
            return 1;
        }
        array_shift($domainParts);
        $domainCount = count($domainParts);
        $zoneCount = count($this->inverseZoneParts);
        if ($domainCount < $zoneCount) {
            return 0;
        }
        for ($i = 0; $i < $zoneCount; $i++) {
            $zonePart = $this->inverseZoneParts[$i];
            $domainPart = $domainParts[$domainCount - $i - 1];
            if ($zonePart !== $domainPart && $zonePart !== '*') {
                return 0;
            }
        }
        return $zoneCount;
    }

    /**
     * @param bool $strict Prefix "=", which makes some servers match the exact name only
     */
    public function buildQuery(string $asciiDomain, bool $strict = false): string
    {
        $query = sprintf($this->queryFormat, $asciiDomain);
        return $strict ? "=$query" : $query;
    }
}
