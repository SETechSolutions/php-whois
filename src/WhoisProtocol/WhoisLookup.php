<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldInfo;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TldResponse;

/**
 * Looks a domain up over WHOIS: asks the zone's servers in turn, retries with a strict query
 * when the answer does not parse, and follows the referral to the registrar's server.
 *
 * @internal
 */
class WhoisLookup
{
    /** @var WhoisClientInterface */
    private $client;

    /** @var ServerList */
    private $servers;

    public function __construct(WhoisClientInterface $client, ServerList $servers)
    {
        $this->client = $client;
        $this->servers = $servers;
    }

    public function hasServerFor(string $asciiDomain): bool
    {
        return (bool)$this->servers->match($asciiDomain);
    }

    /**
     * @param string $asciiDomain
     * @return array [TldResponse, TldInfo|null] The info is null when the answer shows no registered domain
     * @throws WhoisException
     */
    public function lookup(string $asciiDomain): array
    {
        $response = null;
        $info = null;
        $lastError = null;
        foreach ($this->servers->match($asciiDomain) as $server) {
            $this->loadParsedTo($response, $info, $server, $asciiDomain, false, null, $lastError);
            if ($info) {
                break;
            }
        }
        if (!$response && !$info) {
            throw $lastError ?: new WhoisException("No WHOIS response for '$asciiDomain'");
        }
        return [$response, $info];
    }

    /**
     * @param TldResponse|null $outResponse
     * @param TldInfo|null $outInfo
     * @param Server $server
     * @param string $domain
     * @param bool $strict
     * @param string|null $host
     * @param ConnectionException|null $lastError
     * @throws WhoisException
     */
    private function loadParsedTo(&$outResponse, &$outInfo, Server $server, $domain, $strict = false, $host = null, &$lastError = null)
    {
        try {
            $outResponse = $this->request($server, $domain, $strict, $host);
            $outInfo = $server->parser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->host() && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $tmpResponse = null;
            $tmpInfo = null;
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->whoisServer) {
            return;
        }
        $host = $outInfo->whoisServer;
        if ($host && $host != $server->host() && !$server->isCentralized()) {
            $tmpResponse = null;
            $tmpInfo = null;
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }

    /**
     * @param string|null $host Another host to ask with this server's query format and parser (a referral)
     */
    private function request(Server $server, string $domain, bool $strict, $host): TldResponse
    {
        $host = $host ?: $server->host();
        $query = $server->buildQuery($domain, $strict);
        return new TldResponse([
            'domain' => $domain,
            'host' => $host,
            'query' => $query,
            'text' => $this->client->query($host, $query),
        ]);
    }
}
