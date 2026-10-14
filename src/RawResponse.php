<?php

declare(strict_types=1);

namespace SETechSolutions\Whois;

/**
 * What a server answered, unparsed: WHOIS text, or RDAP JSON.
 */
class RawResponse
{
    const SOURCE_RDAP = 'rdap';
    const SOURCE_WHOIS = 'whois';

    /** @var string */
    private $text;

    /** @var string */
    private $source;

    /** @var string */
    private $server;

    /** @var string */
    private $query;

    public function __construct(string $text, string $source, string $server, string $query = '')
    {
        $this->text = $text;
        $this->source = $source;
        $this->server = $server;
        $this->query = $query;
    }

    /**
     * WHOIS text, or RDAP JSON when source() is "rdap". Empty for an RDAP "not found" answer.
     */
    public function text(): string
    {
        return $this->text;
    }

    /**
     * "rdap" or "whois"
     */
    public function source(): string
    {
        return $this->source;
    }

    /**
     * Host name of the server that answered
     */
    public function server(): string
    {
        return $this->server;
    }

    /**
     * What was sent: the WHOIS query line, or the RDAP URL
     */
    public function query(): string
    {
        return $this->query;
    }

    public function __toString(): string
    {
        return $this->text;
    }
}
