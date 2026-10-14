<?php

declare(strict_types=1);

namespace SETechSolutions\Whois;

use InvalidArgumentException;
use SETechSolutions\Whois\Exceptions\InvalidDomainException;
use SETechSolutions\Whois\Exceptions\UnsupportedTldException;
use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\Http\CurlHttpClient;
use SETechSolutions\Whois\Http\HttpClientInterface;
use SETechSolutions\Whois\Rdap\Bootstrap;
use SETechSolutions\Whois\Rdap\RdapLookup;
use SETechSolutions\Whois\WhoisProtocol\Parsing\DomainHelper;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldInfo;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldResponse;
use SETechSolutions\Whois\WhoisProtocol\ServerList;
use SETechSolutions\Whois\WhoisProtocol\WhoisClient;
use SETechSolutions\Whois\WhoisProtocol\WhoisClientInterface;
use SETechSolutions\Whois\WhoisProtocol\WhoisLookup;

/**
 * Looks up domain registration data over RDAP and WHOIS.
 */
class Whois
{
    /** @var array */
    private $options;

    /** @var HttpClientInterface|null */
    private $http;

    /** @var WhoisClientInterface|null */
    private $whoisClient;

    /** @var RdapLookup|null */
    private $rdap;

    /** @var WhoisLookup|null */
    private $whois;

    /**
     * Options, all optional:
     *  - mode: one of the Mode constants (default Mode::RDAP_FIRST)
     *  - timeout: seconds per request (default 30)
     *  - follow_registrar: also ask the registrar's RDAP server when the registry links to it (default true)
     *  - curl_options: extra curl options for every request, e.g. a proxy; WHOIS queries then go through curl too
     *  - rdap_servers: zone => RDAP base URL(s), added to the bundled list
     *  - whois_servers: entries like ['zone' => '.example', 'host' => 'whois.nic.example'], tried before the bundled ones
     *
     * @param array $options
     * @param HttpClientInterface|null $http Replaces the built-in HTTP client
     * @param WhoisClientInterface|null $whoisClient Replaces the built-in WHOIS client
     */
    public function __construct(array $options = [], ?HttpClientInterface $http = null, ?WhoisClientInterface $whoisClient = null)
    {
        $options = array_replace([
            'mode' => Mode::RDAP_FIRST,
            'timeout' => 30,
            'follow_registrar' => true,
            'curl_options' => [],
            'rdap_servers' => [],
            'whois_servers' => [],
        ], array_filter($options, function ($value) {
            return $value !== null;
        }));
        if (!in_array($options['mode'], Mode::all(), true)) {
            throw new InvalidArgumentException(
                "Unknown mode '" . (is_scalar($options['mode']) ? $options['mode'] : gettype($options['mode']))
                . "', use one of: " . implode(', ', Mode::all())
            );
        }
        $options['timeout'] = max(1, (int)$options['timeout']);
        $options['follow_registrar'] = (bool)$options['follow_registrar'];
        $options['curl_options'] = (array)$options['curl_options'];
        $options['rdap_servers'] = (array)$options['rdap_servers'];
        $options['whois_servers'] = (array)$options['whois_servers'];

        $this->options = $options;
        $this->http = $http;
        $this->whoisClient = $whoisClient;
    }

    /**
     * @param string $domain ASCII or international name, e.g. "example.com" or "münchen.de"
     * @return DomainInfo|null Null when the domain is not registered
     * @throws InvalidDomainException
     * @throws UnsupportedTldException
     * @throws WhoisException When the servers cannot be reached or refuse to answer
     */
    public function lookup(string $domain): ?DomainInfo
    {
        list ($raw, $data) = $this->run($this->normalize($domain), false);
        return $data ? new DomainInfo($data, $raw) : null;
    }

    /**
     * @throws InvalidDomainException
     * @throws UnsupportedTldException
     * @throws WhoisException
     */
    public function isAvailable(string $domain): bool
    {
        return $this->lookup($domain) === null;
    }

    /**
     * The unparsed answer. WHOIS text when a WHOIS server answers, RDAP JSON otherwise.
     *
     * @throws InvalidDomainException
     * @throws UnsupportedTldException
     * @throws WhoisException
     */
    public function raw(string $domain): RawResponse
    {
        return $this->run($this->normalize($domain), true)[0];
    }

    /**
     * @return array The options in effect
     */
    public function options(): array
    {
        return $this->options;
    }

    /**
     * @throws InvalidDomainException
     */
    private function normalize(string $domain): string
    {
        $ascii = strtolower(DomainHelper::toAscii(trim($domain)));
        if ($ascii === '' || !preg_match('~^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$~', $ascii)) {
            throw new InvalidDomainException("Not a domain name: '$domain'");
        }
        return $ascii;
    }

    /**
     * @param bool $forRawText raw() prefers WHOIS text when it can get it
     * @return string[]
     */
    private function protocolOrder(bool $forRawText): array
    {
        switch ($this->options['mode']) {
            case Mode::WHOIS_ONLY:
                return [RawResponse::SOURCE_WHOIS];
            case Mode::RDAP_ONLY:
                return [RawResponse::SOURCE_RDAP];
            case Mode::WHOIS_FIRST:
                return [RawResponse::SOURCE_WHOIS, RawResponse::SOURCE_RDAP];
            default:
                return $forRawText
                    ? [RawResponse::SOURCE_WHOIS, RawResponse::SOURCE_RDAP]
                    : [RawResponse::SOURCE_RDAP, RawResponse::SOURCE_WHOIS];
        }
    }

    /**
     * Tries the protocols in the mode's order and returns the first answer. A failure moves on to
     * the next protocol; "not found" is an answer and does not. When every protocol fails, the
     * first one's error is thrown.
     *
     * @return array [RawResponse, array|null]
     * @throws UnsupportedTldException
     * @throws WhoisException
     */
    private function run(string $asciiDomain, bool $forRawText): array
    {
        $firstError = null;
        foreach ($this->protocolOrder($forRawText) as $protocol) {
            try {
                if ($protocol === RawResponse::SOURCE_RDAP) {
                    if ($this->rdap()->hasServerFor($asciiDomain)) {
                        return $this->rdap()->lookup($asciiDomain);
                    }
                } elseif ($this->whois()->hasServerFor($asciiDomain)) {
                    return $this->whoisResult($this->whois()->lookup($asciiDomain));
                }
            } catch (WhoisException $e) {
                $firstError = $firstError ?: $e;
            }
        }
        if ($firstError) {
            throw $firstError;
        }
        throw new UnsupportedTldException("No server is known for '$asciiDomain' in mode '{$this->options['mode']}'");
    }

    /**
     * @param array $result [TldResponse, TldInfo|null]
     * @return array [RawResponse, array|null]
     */
    private function whoisResult(array $result): array
    {
        /** @var TldResponse $response */
        /** @var TldInfo|null $info */
        list ($response, $info) = $result;
        $raw = new RawResponse((string)$response->text, RawResponse::SOURCE_WHOIS, (string)$response->host, (string)$response->query);
        if (!$info) {
            return [$raw, null];
        }
        return [$raw, [
            'domain' => (string)$info->domainName,
            'registrar' => (string)$info->registrar,
            'owner' => (string)$info->owner,
            'createdAt' => (int)$info->creationDate,
            'updatedAt' => (int)$info->updatedDate,
            'expiresAt' => (int)$info->expirationDate,
            'nameServers' => (array)$info->nameServers,
            'statuses' => (array)$info->states,
            'dnssec' => (string)$info->dnssec,
            'whoisServer' => (string)$info->whoisServer,
        ]];
    }

    private function rdap(): RdapLookup
    {
        if (!$this->rdap) {
            $http = $this->http ?: new CurlHttpClient($this->options['timeout'], $this->options['curl_options']);
            $bootstrap = Bootstrap::bundled()->addServers($this->options['rdap_servers']);
            $this->rdap = new RdapLookup($http, $bootstrap, $this->options['follow_registrar']);
        }
        return $this->rdap;
    }

    private function whois(): WhoisLookup
    {
        if (!$this->whois) {
            $client = $this->whoisClient ?: new WhoisClient($this->options['timeout'], $this->options['curl_options']);
            $this->whois = new WhoisLookup($client, ServerList::bundled($this->options['whois_servers']));
        }
        return $this->whois;
    }
}
