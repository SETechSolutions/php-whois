<?php

declare(strict_types=1);

namespace SETechSolutions\Whois;

use DateTimeImmutable;
use DateTimeZone;
use JsonSerializable;
use SETechSolutions\Whois\WhoisProtocol\Parsing\DomainHelper;

/**
 * What is known about a registered domain. Immutable.
 * Fields a registry does not publish are empty: '' for text, [] for lists, null for dates.
 */
class DomainInfo implements JsonSerializable
{
    /** @var array */
    private $data;

    /** @var RawResponse */
    private $raw;

    /**
     * @internal Created by Whois::lookup()
     *
     * @param array $data Keys: domain, registrar, owner, whoisServer, dnssec (strings),
     *                    nameServers, statuses (string lists), createdAt, updatedAt, expiresAt (unix time or 0)
     * @param RawResponse $raw
     */
    public function __construct(array $data, RawResponse $raw)
    {
        $this->data = $data;
        $this->raw = $raw;
    }

    /**
     * The domain name in ASCII form (punycode for international names), lowercase
     */
    public function domain(): string
    {
        return (string)($this->data['domain'] ?? '');
    }

    /**
     * The domain name with international characters, e.g. "münchen.de"
     */
    public function unicodeDomain(): string
    {
        return DomainHelper::toUnicode($this->domain());
    }

    public function registrar(): string
    {
        return (string)($this->data['registrar'] ?? '');
    }

    /**
     * The registrant's organization or name. Often empty: registries hide it for privacy.
     */
    public function owner(): string
    {
        return (string)($this->data['owner'] ?? '');
    }

    /**
     * In UTC. Null when the registry does not publish it.
     */
    public function createdAt(): ?DateTimeImmutable
    {
        return $this->date('createdAt');
    }

    /**
     * In UTC. Null when the registry does not publish it.
     */
    public function updatedAt(): ?DateTimeImmutable
    {
        return $this->date('updatedAt');
    }

    /**
     * In UTC. Null when the registry does not publish it.
     */
    public function expiresAt(): ?DateTimeImmutable
    {
        return $this->date('expiresAt');
    }

    /**
     * @return string[] Lowercase host names
     */
    public function nameServers(): array
    {
        return array_values((array)($this->data['nameServers'] ?? []));
    }

    /**
     * @return string[] Lowercase status codes as WHOIS shows them, e.g. "clienttransferprohibited", "ok"
     */
    public function statuses(): array
    {
        return array_values((array)($this->data['statuses'] ?? []));
    }

    /**
     * As the registry states it, e.g. "unsigned" or "signedDelegation"; '' when not stated
     */
    public function dnssec(): string
    {
        return (string)($this->data['dnssec'] ?? '');
    }

    /**
     * The registrar's or registry's WHOIS server, when the answer names one
     */
    public function whoisServer(): string
    {
        return (string)($this->data['whoisServer'] ?? '');
    }

    /**
     * Which protocol answered: "rdap" or "whois"
     */
    public function source(): string
    {
        return $this->raw->source();
    }

    public function raw(): RawResponse
    {
        return $this->raw;
    }

    /**
     * Dates are ISO 8601 strings or null. The raw response is not included.
     */
    public function toArray(): array
    {
        return [
            'domain' => $this->domain(),
            'registrar' => $this->registrar(),
            'owner' => $this->owner(),
            'createdAt' => $this->formatDate($this->createdAt()),
            'updatedAt' => $this->formatDate($this->updatedAt()),
            'expiresAt' => $this->formatDate($this->expiresAt()),
            'nameServers' => $this->nameServers(),
            'statuses' => $this->statuses(),
            'dnssec' => $this->dnssec(),
            'whoisServer' => $this->whoisServer(),
            'source' => $this->source(),
        ];
    }

    /**
     * @return array
     */
    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    private function date(string $key): ?DateTimeImmutable
    {
        $time = (int)($this->data[$key] ?? 0);
        if ($time <= 0) {
            return null;
        }
        return (new DateTimeImmutable('@' . $time))->setTimezone(new DateTimeZone('UTC'));
    }

    private function formatDate(?DateTimeImmutable $date): ?string
    {
        return $date ? $date->format(DATE_ATOM) : null;
    }
}
