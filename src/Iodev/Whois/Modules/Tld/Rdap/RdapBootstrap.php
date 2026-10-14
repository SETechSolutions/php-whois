<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Rdap;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\IHttpLoader;

/**
 * Maps zones to RDAP base URLs, from IANA's bootstrap file (RFC 9224).
 * The package ships a snapshot of it in Configs/module.tld.rdap.json.
 */
class RdapBootstrap
{
    const IANA_DNS_URL = 'https://data.iana.org/rdap/dns.json';

    /**
     * @param array $data Decoded IANA bootstrap file
     * @return static
     */
    public static function fromIanaData(array $data)
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
        return new static($servers);
    }

    /**
     * Downloads the current bootstrap file from IANA. Cache the result: IANA asks clients
     * not to fetch it more than once a day.
     *
     * @param IHttpLoader $loader
     * @param string $url
     * @return static
     * @throws ConnectionException
     * @throws WhoisException
     */
    public static function loadFromIana(IHttpLoader $loader, $url = self::IANA_DNS_URL)
    {
        $result = $loader->loadHttp($url);
        $data = json_decode($result['body'], true);
        if ($result['status'] !== 200 || !is_array($data)) {
            throw new WhoisException("Cannot load RDAP bootstrap file from $url (HTTP {$result['status']})");
        }
        return static::fromIanaData($data);
    }

    /**
     * @param array $servers Zone => base URLs, e.g. ['com' => ['https://rdap.verisign.com/com/v1/']]
     */
    public function __construct(array $servers = [])
    {
        $this->setServers($servers);
    }

    /** @var string[][] */
    protected $servers = [];

    /**
     * @return string[][]
     */
    public function getServers()
    {
        return $this->servers;
    }

    /**
     * @param array $servers Zone => base URL or list of base URLs
     * @return $this
     */
    public function setServers(array $servers)
    {
        $this->servers = [];
        return $this->addServers($servers);
    }

    /**
     * Adds zones; a zone that is already known gets the new URLs instead of the old ones.
     *
     * @param array $servers Zone => base URL or list of base URLs
     * @return $this
     */
    public function addServers(array $servers)
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
     * Base URLs of the most specific zone that matches the domain, or an empty list.
     *
     * @param string $domain
     * @return string[]
     */
    public function matchUrls($domain)
    {
        $labels = explode('.', strtolower(DomainHelper::toAscii($domain)));
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
