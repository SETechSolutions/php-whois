<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld\Parsers;

use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Modules\Tld\TldInfo;
use Iodev\Whois\Modules\Tld\TldParser;
use Iodev\Whois\Modules\Tld\TldResponse;

/**
 * Parses an RDAP domain response (RFC 9083) into the same TldInfo fields the WHOIS parsers fill,
 * in the same formats: unix timestamps, lowercase EPP states, "unsigned" / "signedDelegation".
 * The decoded JSON is available as $info->getExtraVal('rdap').
 */
class RdapParser extends TldParser
{
    /** @var string Owner names matching this are placeholders, not names */
    protected $redactedPattern = '~redact|withheld|not\s+disclosed|non-public|data\s+protected~ui';

    /** @var array RDAP status => the EPP status WHOIS shows (RFC 8056), others just lose their spaces */
    protected $statesMap = [
        'active' => 'ok',
    ];

    /**
     * @return string
     */
    public function getType()
    {
        return TldParser::RDAP;
    }

    /**
     * @param array $cfg
     * @return $this
     */
    public function setConfig($cfg)
    {
        foreach ($cfg as $k => $v) {
            $this->{$k} = $v;
        }
        return $this;
    }

    /**
     * @param TldResponse $response
     * @return TldInfo|null
     */
    public function parseResponse(TldResponse $response)
    {
        $json = json_decode($response->text, true);
        if (!is_array($json) || ($json['objectClassName'] ?? '') !== 'domain') {
            return null;
        }
        $data = [
            'parserType' => $this->getType(),
            'domainName' => $this->parseDomainName($json, $response->domain),
            'whoisServer' => strtolower(trim((string)($json['port43'] ?? ''), '.')),
            'nameServers' => $this->parseNameServers($json),
            'dnssec' => $this->parseDnssec($json),
            'creationDate' => $this->findEventTime($json, 'registration'),
            'expirationDate' => $this->findEventTime($json, 'expiration'),
            'updatedDate' => $this->findEventTime($json, 'last changed'),
            'owner' => $this->parseOwner($json),
            'registrar' => $this->parseRegistrar($json),
            'states' => $this->parseStates($json),
        ];
        $info = $this->createDomainInfo($response, $data, ['rdap' => $json]);
        return $info->isValuable() ? $info : null;
    }

    /**
     * @param TldResponse $response
     * @param array $data
     * @param array $options
     * @return TldInfo
     */
    protected function createDomainInfo(TldResponse $response, array $data, $options = [])
    {
        return new TldInfo($response, $data, $options);
    }

    /**
     * @param array $json
     * @param string $fallback
     * @return string
     */
    protected function parseDomainName(array $json, $fallback)
    {
        $name = (string)($json['ldhName'] ?? $json['unicodeName'] ?? $fallback);
        return strtolower(DomainHelper::toAscii($name));
    }

    /**
     * @param array $json
     * @return string[]
     */
    protected function parseNameServers(array $json)
    {
        $servers = [];
        foreach ($json['nameservers'] ?? [] as $ns) {
            $name = (string)($ns['ldhName'] ?? $ns['unicodeName'] ?? '');
            $name = strtolower(DomainHelper::toAscii(trim($name, '.')));
            if ($name !== '') {
                $servers[$name] = $name;
            }
        }
        return array_values($servers);
    }

    /**
     * @param array $json
     * @return string
     */
    protected function parseDnssec(array $json)
    {
        if (!isset($json['secureDNS']['delegationSigned'])) {
            return '';
        }
        return $json['secureDNS']['delegationSigned'] ? 'signedDelegation' : 'unsigned';
    }

    /**
     * @param array $json
     * @param string $action
     * @return int
     */
    protected function findEventTime(array $json, $action)
    {
        foreach ($json['events'] ?? [] as $event) {
            if (strtolower($event['eventAction'] ?? '') === $action && !empty($event['eventDate'])) {
                $time = strtotime((string)$event['eventDate']);
                return $time === false ? 0 : $time;
            }
        }
        return 0;
    }

    /**
     * @param array $json
     * @return string[]
     */
    protected function parseStates(array $json)
    {
        $states = [];
        foreach ($json['status'] ?? [] as $status) {
            $status = strtolower(trim((string)$status));
            $state = $this->statesMap[$status] ?? str_replace(' ', '', $status);
            if ($state !== '') {
                $states[$state] = $state;
            }
        }
        return array_values($states);
    }

    /**
     * @param array $json
     * @return string
     */
    protected function parseRegistrar(array $json)
    {
        $entity = $this->findEntity($json, 'registrar');
        if (!$entity) {
            return '';
        }
        return $this->getVcardValue($entity, 'fn') ?: $this->getVcardValue($entity, 'org');
    }

    /**
     * @param array $json
     * @return string
     */
    protected function parseOwner(array $json)
    {
        $entity = $this->findEntity($json, 'registrant');
        if (!$entity) {
            return '';
        }
        foreach (['org', 'fn'] as $key) {
            $value = $this->getVcardValue($entity, $key);
            if ($value !== '' && !preg_match($this->redactedPattern, $value)) {
                return $value;
            }
        }
        return '';
    }

    /**
     * @param array $json
     * @param string $role
     * @return array|null
     */
    protected function findEntity(array $json, $role)
    {
        foreach ($json['entities'] ?? [] as $entity) {
            if (in_array($role, $entity['roles'] ?? [], true)) {
                return $entity;
            }
        }
        return null;
    }

    /**
     * @param array $entity
     * @param string $key
     * @return string
     */
    protected function getVcardValue(array $entity, $key)
    {
        foreach ($entity['vcardArray'][1] ?? [] as $prop) {
            if (!is_array($prop) || ($prop[0] ?? '') !== $key) {
                continue;
            }
            $value = $prop[3] ?? '';
            // Structured values such as org units come as lists
            $value = is_array($value) ? implode(' ', array_filter(array_map('strval', $value))) : (string)$value;
            return trim($value);
        }
        return '';
    }
}
