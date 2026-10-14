<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Rdap;

use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\Http\HttpClientInterface;
use SETechSolutions\Whois\Resources;

/**
 * Maps zones to RDAP base URLs, from IANA's bootstrap file (RFC 9224).
 * The package ships a snapshot of it in resources/rdap-bootstrap.json.
 */
class Bootstrap
{
    const IANA_DNS_URL = 'https://data.iana.org/rdap/dns.json';

    /** @var string[][] Zone => base URLs */
    private $servers = [];

    /**
     * @param array $servers Zone => base URL or list of base URLs, e.g. ['com' => 'https://rdap.verisign.com/com/v1/']
     */
    public function __construct(array $servers = [])
    {
        $this->addServers($servers);
    }

    /**
     * The snapshot shipped with the package
     */
    public static function bundled(): self
    {
        return self::fromIanaData(Resources::load('rdap-bootstrap'));
    }

    /**
     * @param array $data Decoded IANA bootstrap file
     */
    public static function fromIanaData(array $data): self
    {
        $servers = [];
        foreach ($data['services'] ?? [] as $service) {
            if (!is_array($service) || count($service) < 2) {
                continue;
            }
            list ($zones, $urls) = $service;
            foreach ((array)$zones as $zone) {
                $servers[$zone] = array_merge($servers[$zone] ?? [], (array)$urls);
            }
        }
        return new self($servers);
    }

    /**
     * Downloads the current file from IANA. Cache the result: IANA asks clients not to
     * fetch it more than once a day.
     *
     * @throws WhoisException
     */
    public static function fromIana(HttpClientInterface $http, string $url = self::IANA_DNS_URL): self
    {
        $result = $http->get($url);
        $data = json_decode($result['body'], true);
        if ((int)$result['status'] !== 200 || !is_array($data)) {
            throw new WhoisException("Cannot load the RDAP bootstrap file from $url (HTTP {$result['status']})");
        }
        return self::fromIanaData($data);
    }

    /**
     * Adds zones; a zone that is already known gets the new URLs instead of the old ones.
     *
     * @param array $servers Zone => base URL or list of base URLs
     * @return $this
     */
    public function addServers(array $servers): self
    {
        foreach ($servers as $zone => $urls) {
            $zone = strtolower(trim((string)$zone, '.'));
            $urls = array_values(array_filter(array_map('strval', (array)$urls)));
            if ($zone === '' || !$urls) {
                continue;
            }
            // HTTPS first; http-only servers stay as a last resort
            usort($urls, function ($a, $b) {
                return (int)(stripos($b, 'https://') === 0) - (int)(stripos($a, 'https://') === 0);
            });
            $this->servers[$zone] = $urls;
        }
        return $this;
    }

    /**
     * @return string[][] Zone => base URLs
     */
    public function servers(): array
    {
        return $this->servers;
    }

    /**
     * Base URLs of the most specific zone that matches the domain, or an empty list.
     *
     * @param string $asciiDomain
     * @return string[]
     */
    public function match(string $asciiDomain): array
    {
        $labels = explode('.', strtolower($asciiDomain));
        // The zone has at least one label less than the domain
        for ($i = 1; $i < count($labels); $i++) {
            $zone = implode('.', array_slice($labels, $i));
            if (isset($this->servers[$zone])) {
                return $this->servers[$zone];
            }
        }
        return [];
    }
}
