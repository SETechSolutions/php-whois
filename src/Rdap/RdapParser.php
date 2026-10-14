<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Rdap;

use SETechSolutions\Whois\WhoisProtocol\Parsing\DomainHelper;

/**
 * Reads an RDAP domain response (RFC 9083) into the fields DomainInfo holds, in the formats the
 * WHOIS parsers produce: unix times, lowercase EPP statuses, "unsigned" / "signedDelegation".
 *
 * @internal
 */
class RdapParser
{
    /** Owner names matching this are placeholders, not names */
    const REDACTED_PATTERN = '~redact|withheld|not\s+disclosed|non-public|data\s+protected~ui';

    /** RDAP status => the EPP status WHOIS shows (RFC 8056); others just lose their spaces */
    const STATUS_MAP = [
        'active' => 'ok',
    ];

    /**
     * @param string $body RDAP JSON
     * @param string $fallbackDomain Used when the response names no domain
     * @return array|null Null when the body is not an RDAP domain object
     */
    public function parse(string $body, string $fallbackDomain): ?array
    {
        $json = json_decode($body, true);
        if (!is_array($json) || ($json['objectClassName'] ?? '') !== 'domain') {
            return null;
        }
        $name = (string)($json['ldhName'] ?? $json['unicodeName'] ?? $fallbackDomain);
        return [
            'domain' => strtolower(DomainHelper::toAscii($name)),
            'registrar' => $this->registrar($json),
            'owner' => $this->owner($json),
            'createdAt' => $this->eventTime($json, 'registration'),
            'updatedAt' => $this->eventTime($json, 'last changed'),
            'expiresAt' => $this->eventTime($json, 'expiration'),
            'nameServers' => $this->nameServers($json),
            'statuses' => $this->statuses($json),
            'dnssec' => $this->dnssec($json),
            'whoisServer' => strtolower(trim((string)($json['port43'] ?? ''), '.')),
            'relatedUrl' => $this->relatedUrl($json),
        ];
    }

    private function nameServers(array $json): array
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

    private function dnssec(array $json): string
    {
        if (!isset($json['secureDNS']['delegationSigned'])) {
            return '';
        }
        return $json['secureDNS']['delegationSigned'] ? 'signedDelegation' : 'unsigned';
    }

    private function eventTime(array $json, string $action): int
    {
        foreach ($json['events'] ?? [] as $event) {
            if (strtolower((string)($event['eventAction'] ?? '')) === $action && !empty($event['eventDate'])) {
                $time = strtotime((string)$event['eventDate']);
                return $time === false ? 0 : $time;
            }
        }
        return 0;
    }

    private function statuses(array $json): array
    {
        $statuses = [];
        foreach ($json['status'] ?? [] as $status) {
            $status = strtolower(trim((string)$status));
            $mapped = self::STATUS_MAP[$status] ?? str_replace(' ', '', $status);
            if ($mapped !== '') {
                $statuses[$mapped] = $mapped;
            }
        }
        return array_values($statuses);
    }

    private function registrar(array $json): string
    {
        $entity = $this->entity($json, 'registrar');
        if (!$entity) {
            return '';
        }
        return $this->vcardValue($entity, 'fn') ?: $this->vcardValue($entity, 'org');
    }

    private function owner(array $json): string
    {
        $entity = $this->entity($json, 'registrant');
        if (!$entity) {
            return '';
        }
        foreach (['org', 'fn'] as $key) {
            $value = $this->vcardValue($entity, $key);
            if ($value !== '' && !preg_match(self::REDACTED_PATTERN, $value)) {
                return $value;
            }
        }
        return '';
    }

    private function entity(array $json, string $role): ?array
    {
        foreach ($json['entities'] ?? [] as $entity) {
            if (is_array($entity) && in_array($role, (array)($entity['roles'] ?? []), true)) {
                return $entity;
            }
        }
        return null;
    }

    private function vcardValue(array $entity, string $key): string
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

    /**
     * The registrar's RDAP URL for the same domain, which registries such as .com link to.
     */
    private function relatedUrl(array $json): string
    {
        foreach ($json['links'] ?? [] as $link) {
            $href = (string)($link['href'] ?? '');
            $type = strtolower((string)($link['type'] ?? ''));
            if (($link['rel'] ?? '') !== 'related' || !preg_match('~^https?://~i', $href)) {
                continue;
            }
            if ($type === '' || strpos($type, 'json') !== false) {
                return $href;
            }
        }
        return '';
    }
}
