<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Factory;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Helpers\LoaderHelper;
use Iodev\Whois\Loaders\IHttpLoader;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;
use Iodev\Whois\Modules\Tld\Rdap\RdapBootstrap;
use InvalidArgumentException;

class TldModule extends Module
{
    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        parent::__construct(ModuleType::TLD, $loader);
    }

    /** @var TldServer[] */
    protected $servers = [];

    /** @var TldServer[] */
    protected $lastUsedServers = [];

    /** @var string */
    protected $lookupMode = LookupMode::RDAP_FIRST;

    /** @var RdapBootstrap|null */
    protected $rdapBootstrap;

    /** @var TldParser|null */
    protected $rdapParser;

    /** @var IHttpLoader|null */
    protected $httpLoader;

    /** @var bool */
    protected $rdapFollowRelated = true;

    /**
     * @return string One of the LookupMode constants
     */
    public function getLookupMode()
    {
        return $this->lookupMode;
    }

    /**
     * @param string $mode One of the LookupMode constants
     * @return $this
     */
    public function setLookupMode($mode)
    {
        if (!in_array($mode, LookupMode::all(), true)) {
            throw new InvalidArgumentException("Unknown lookup mode '$mode'");
        }
        $this->lookupMode = $mode;
        return $this;
    }

    /**
     * @return RdapBootstrap
     */
    public function getRdapBootstrap()
    {
        $this->rdapBootstrap = $this->rdapBootstrap ?: Factory::get()->createRdapBootstrap();
        return $this->rdapBootstrap;
    }

    /**
     * @param RdapBootstrap $bootstrap
     * @return $this
     */
    public function setRdapBootstrap(RdapBootstrap $bootstrap)
    {
        $this->rdapBootstrap = $bootstrap;
        return $this;
    }

    /**
     * @return TldParser
     */
    public function getRdapParser()
    {
        $this->rdapParser = $this->rdapParser ?: Factory::get()->createTldParser(TldParser::RDAP);
        return $this->rdapParser;
    }

    /**
     * @param TldParser $parser
     * @return $this
     */
    public function setRdapParser(TldParser $parser)
    {
        $this->rdapParser = $parser;
        return $this;
    }

    /**
     * The loader for RDAP requests: the one set with setHttpLoader(), or the module's loader when it
     * supports HTTP (see LoaderHelper::getHttpLoader()). Null means RDAP is not used.
     *
     * @return IHttpLoader|null
     */
    public function getHttpLoader()
    {
        return $this->httpLoader ?: LoaderHelper::getHttpLoader($this->getLoader());
    }

    /**
     * @param IHttpLoader|null $loader
     * @return $this
     */
    public function setHttpLoader(?IHttpLoader $loader)
    {
        $this->httpLoader = $loader;
        return $this;
    }

    /**
     * @return bool
     */
    public function isRdapFollowRelated()
    {
        return $this->rdapFollowRelated;
    }

    /**
     * Whether to also ask the registrar's RDAP server, which registries such as .com link to.
     * It adds a second request but usually fills in the owner and the registrar's WHOIS server.
     *
     * @param bool $follow
     * @return $this
     */
    public function setRdapFollowRelated($follow)
    {
        $this->rdapFollowRelated = (bool)$follow;
        return $this;
    }

    /**
     * @return TldServer[]
     */
    public function getServers()
    {
        return $this->servers;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers()
    {
        return $this->lastUsedServers;
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function addServers($servers)
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function setServers($servers)
    {
        $weightMap = [];
        foreach ($servers as $index => $server) {
            $parts = explode('.', $server->getZone());
            $rootZone = array_pop($parts);
            $subZone1 = $parts ? array_pop($parts) : '';
            $subZone2 = $parts ? array_pop($parts) : '';
            $weightMap[$server->getId()] = sprintf('%16s.%16s.%32s.%13s', $subZone2, $subZone1, $rootZone, 1000000 - $index);
        };
        usort($servers, function(TldServer $a, TldServer $b) use ($weightMap) {
            return strcmp($weightMap[$b->getId()], $weightMap[$a->getId()]);
        });
        $this->servers = $servers;
        return $this;
    }

    /**
     * @param string $domain
     * @param bool $quiet
     * @return TldServer[]
     * @throws ServerMismatchException
     */
    public function matchServers($domain, $quiet = false)
    {
        $domainAscii = DomainHelper::toAscii($domain);
        $servers = [];
        foreach ($this->servers as $server) {
            $matchedCount = $server->matchDomainZone($domainAscii);
            if ($matchedCount) {
                $servers[] = $server;
            }
        }
        if (!$quiet && empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        return $servers;
    }

    /**
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable($domain)
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldResponse
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain($domain, ?TldServer $server = null)
    {
        if ($server) {
            list ($response) = $this->loadDomainData($domain, [$server]);
            return $response;
        }
        list ($response) = $this->loadDomainDataByMode($domain, true);
        return $response;
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo($domain, ?TldServer $server = null)
    {
        if ($server) {
            list (, $info) = $this->loadDomainData($domain, [$server]);
            return $info;
        }
        list (, $info) = $this->loadDomainDataByMode($domain, false);
        return $info;
    }

    /**
     * @param string $domain
     * @return string[]
     */
    public function matchRdapUrls($domain)
    {
        return $this->getRdapBootstrap()->matchUrls($domain);
    }

    /**
     * @param bool $forRawText lookupDomain() wants WHOIS text when it can get it
     * @return string[]
     */
    protected function getProtocolOrder($forRawText)
    {
        switch ($this->lookupMode) {
            case LookupMode::WHOIS_ONLY:
                return [TldResponse::SOURCE_WHOIS];
            case LookupMode::RDAP_ONLY:
                return [TldResponse::SOURCE_RDAP];
            case LookupMode::WHOIS_FIRST:
                return [TldResponse::SOURCE_WHOIS, TldResponse::SOURCE_RDAP];
            default:
                return $forRawText
                    ? [TldResponse::SOURCE_WHOIS, TldResponse::SOURCE_RDAP]
                    : [TldResponse::SOURCE_RDAP, TldResponse::SOURCE_WHOIS];
        }
    }

    /**
     * Tries the protocols in the lookup mode's order and returns the first answer.
     * A failure (ConnectionException or WhoisException) moves on to the next protocol;
     * "not found" is an answer and does not. When every protocol fails, the first one's error is thrown.
     *
     * @param string $domain
     * @param bool $forRawText
     * @return array [TldResponse, TldInfo|null]
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadDomainDataByMode($domain, $forRawText)
    {
        $this->lastUsedServers = [];
        $firstError = null;
        foreach ($this->getProtocolOrder($forRawText) as $protocol) {
            try {
                if ($protocol === TldResponse::SOURCE_RDAP) {
                    $urls = $this->getHttpLoader() ? $this->matchRdapUrls($domain) : [];
                    if ($urls) {
                        return $this->loadRdapData($domain, $urls);
                    }
                } else {
                    $servers = $this->matchServers($domain, true);
                    if ($servers) {
                        return $this->loadDomainData($domain, $servers);
                    }
                }
            } catch (ConnectionException $e) {
                $firstError = $firstError ?: $e;
            } catch (WhoisException $e) {
                $firstError = $firstError ?: $e;
            }
        }
        if ($firstError) {
            throw $firstError;
        }
        throw new ServerMismatchException("No servers matched for domain '$domain'");
    }

    /**
     * @param string $url
     * @param string $domain
     * @return TldResponse An RDAP response; HTTP status 404 means the domain was not found
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadRdapResponse($url, $domain)
    {
        $httpLoader = $this->getHttpLoader();
        if (!$httpLoader) {
            throw new ConnectionException('The loader does not support HTTP, RDAP is not available');
        }
        $result = $httpLoader->loadHttp($url);
        $status = (int)$result['status'];
        $host = (string)parse_url($url, PHP_URL_HOST);
        if ($status === 429) {
            throw new WhoisException("RDAP rate limit exceeded: $host", $status);
        }
        if ($status >= 500 || $status === 0) {
            throw new ConnectionException("RDAP server error (HTTP $status): $host", $status);
        }
        if ($status !== 200 && $status !== 404) {
            throw new WhoisException("RDAP request failed (HTTP $status): $url", $status);
        }
        return new TldResponse([
            'domain' => $domain,
            'host' => $host,
            'query' => $url,
            'text' => $result['body'],
            'source' => TldResponse::SOURCE_RDAP,
            'httpStatus' => $status,
        ]);
    }

    /**
     * @param string $domain
     * @param string[] $baseUrls Tried in order until one answers
     * @return array [TldResponse, TldInfo|null] The info is null when the domain is not registered
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadRdapData($domain, array $baseUrls)
    {
        $domain = DomainHelper::toAscii($domain);
        $lastError = null;
        foreach ($baseUrls as $baseUrl) {
            $url = rtrim($baseUrl, '/') . '/domain/' . rawurlencode($domain);
            try {
                $response = $this->loadRdapResponse($url, $domain);
            } catch (ConnectionException $e) {
                $lastError = $e;
                continue;
            }
            if ($response->getHttpStatus() === 404) {
                return [$response, null];
            }
            $info = $this->getRdapParser()->parseResponse($response);
            if (!$info) {
                throw new WhoisException("Unexpected RDAP response from {$response->host}");
            }
            if ($this->rdapFollowRelated) {
                $info = $this->loadRdapRelatedInfo($info);
            }
            return [$response, $info];
        }
        throw $lastError ?: new WhoisException('No RDAP response');
    }

    /**
     * Adds the registrar's data when the registry links to the registrar's RDAP server.
     * The registry's values win, except the owner and the WHOIS server, which only the registrar has
     * for thin registries. Errors are ignored: the registry's answer is enough.
     *
     * @param TldInfo $info
     * @return TldInfo
     */
    protected function loadRdapRelatedInfo(TldInfo $info)
    {
        $url = $this->findRdapRelatedUrl($info);
        if (!$url) {
            return $info;
        }
        try {
            $response = $this->loadRdapResponse($url, $info->getResponse()->domain);
        } catch (ConnectionException $e) {
            return $info;
        } catch (WhoisException $e) {
            return $info;
        }
        $related = $response->getHttpStatus() === 200
            ? $this->getRdapParser()->parseResponse($response)
            : null;
        if (!$related) {
            return $info;
        }
        $data = $info->getData();
        foreach ($related->getData() as $key => $value) {
            if (empty($data[$key]) || (in_array($key, ['owner', 'whoisServer'], true) && !empty($value))) {
                $data[$key] = $value;
            }
        }
        return new TldInfo($info->getResponse(), $data, array_merge($info->getExtra(), [
            'relatedResponse' => $response,
            'relatedInfo' => $related,
        ]));
    }

    /**
     * @param TldInfo $info
     * @return string|null
     */
    protected function findRdapRelatedUrl(TldInfo $info)
    {
        $json = $info->getExtraVal('rdap', []);
        $host = $info->getResponse()->host;
        foreach ($json['links'] ?? [] as $link) {
            $href = (string)($link['href'] ?? '');
            $type = strtolower((string)($link['type'] ?? ''));
            if (($link['rel'] ?? '') !== 'related' || !preg_match('~^https?://~i', $href)) {
                continue;
            }
            if ($type !== '' && strpos($type, 'json') === false) {
                continue;
            }
            if (strcasecmp((string)parse_url($href, PHP_URL_HOST), $host) !== 0) {
                return $href;
            }
        }
        return null;
    }

    /**
     * @param TldServer $server
     * @param string $domain
     * @param bool $strict
     * @param string $host
     * @return TldResponse
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadResponse(TldServer $server, $domain, $strict = false, $host = null)
    {
        $host = $host ?: $server->getHost();
        $query = $server->buildDomainQuery($domain, $strict);
        return new TldResponse([
            'domain' => $domain,
            'host' => $host,
            'query' => $query,
            'text' => $this->getLoader()->loadText($host, $query),
        ]);
    }

    /**
     * @param string $domain
     * @param TldServer[] $servers
     * @return array
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainData(string $domain, array $servers): array
    {
        $this->lastUsedServers = [];
        $domain = DomainHelper::toAscii($domain);
        $response = null;
        $info = null;
        $lastError = null;
        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;
            $this->loadParsedTo($response, $info, $server, $domain, false, null, $lastError);
            if ($info) {
                break;
            }
        }
        if (!$response && !$info) {
            throw $lastError ? $lastError : new WhoisException("No response");
        }
        return [$response, $info];
    }

    /**
     * @param $outResponse
     * @param TldInfo $outInfo
     * @param TldServer $server
     * @param $domain
     * @param $strict
     * @param $host
     * @param $lastError
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadParsedTo(&$outResponse, &$outInfo, $server, $domain, $strict = false, $host = null, &$lastError = null)
    {
        try {
            $outResponse = $this->loadResponse($server, $domain, $strict, $host);
            $outInfo = $server->getParser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->getHost() && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->whoisServer) {
            return;
        }
        $host = $outInfo->whoisServer;
        if ($host && $host != $server->getHost() && !$server->isCentralized()) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }
}
