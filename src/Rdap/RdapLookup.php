<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Rdap;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Exceptions\RateLimitException;
use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\Http\HttpClientInterface;
use SETechSolutions\Whois\RawResponse;

/**
 * Looks a domain up over RDAP.
 *
 * @internal
 */
class RdapLookup
{
    /** @var HttpClientInterface */
    private $http;

    /** @var Bootstrap */
    private $bootstrap;

    /** @var bool */
    private $followRegistrar;

    /** @var RdapParser */
    private $parser;

    public function __construct(HttpClientInterface $http, Bootstrap $bootstrap, bool $followRegistrar = true)
    {
        $this->http = $http;
        $this->bootstrap = $bootstrap;
        $this->followRegistrar = $followRegistrar;
        $this->parser = new RdapParser();
    }

    public function hasServerFor(string $asciiDomain): bool
    {
        return (bool)$this->bootstrap->match($asciiDomain);
    }

    /**
     * @param string $asciiDomain
     * @return array [RawResponse, array|null] The data is null when the domain is not registered
     * @throws WhoisException
     */
    public function lookup(string $asciiDomain): array
    {
        $lastError = null;
        foreach ($this->bootstrap->match($asciiDomain) as $baseUrl) {
            $url = rtrim($baseUrl, '/') . '/domain/' . rawurlencode($asciiDomain);
            try {
                list ($status, $raw) = $this->request($url);
            } catch (ConnectionException $e) {
                // The zone may list more than one server
                $lastError = $e;
                continue;
            }
            if ($status === 404) {
                return [$raw, null];
            }
            $data = $this->parser->parse($raw->text(), $asciiDomain);
            if (!$data) {
                throw new WhoisException("Unexpected RDAP response from {$raw->server()}");
            }
            if ($this->followRegistrar) {
                $data = $this->addRegistrarData($data, $raw->server(), $asciiDomain);
            }
            unset($data['relatedUrl']);
            return [$raw, $data];
        }
        throw $lastError ?: new WhoisException("No RDAP server for '$asciiDomain'");
    }

    /**
     * @return array [int status (200 or 404), RawResponse]
     * @throws WhoisException
     */
    private function request(string $url): array
    {
        $result = $this->http->get($url);
        $status = (int)$result['status'];
        $host = (string)parse_url($url, PHP_URL_HOST);
        if ($status === 429) {
            throw new RateLimitException("RDAP rate limit exceeded: $host", $status);
        }
        if ($status >= 500 || $status === 0) {
            throw new ConnectionException("RDAP server error (HTTP $status): $host", $status);
        }
        if ($status !== 200 && $status !== 404) {
            throw new WhoisException("RDAP request failed (HTTP $status): $url", $status);
        }
        return [$status, new RawResponse((string)$result['body'], RawResponse::SOURCE_RDAP, $host, $url)];
    }

    /**
     * Asks the registrar's RDAP server when the registry links to one. The registry's values win,
     * except the owner and the WHOIS server, which only the registrar has for registries such as .com.
     * Errors are ignored: the registry's answer is enough.
     */
    private function addRegistrarData(array $data, string $registryHost, string $asciiDomain): array
    {
        $url = (string)($data['relatedUrl'] ?? '');
        if ($url === '' || strcasecmp((string)parse_url($url, PHP_URL_HOST), $registryHost) === 0) {
            return $data;
        }
        try {
            list ($status, $raw) = $this->request($url);
        } catch (WhoisException $e) {
            return $data;
        }
        $registrar = $status === 200 ? $this->parser->parse($raw->text(), $asciiDomain) : null;
        if (!$registrar) {
            return $data;
        }
        foreach ($registrar as $key => $value) {
            if (empty($data[$key]) || (in_array($key, ['owner', 'whoisServer'], true) && !empty($value))) {
                $data[$key] = $value;
            }
        }
        return $data;
    }
}
