<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Fakes;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\WhoisProtocol\WhoisClientInterface;

class FakeWhoisClient implements WhoisClientInterface
{
    /** @var string Answer of every server */
    public $text = '';

    /** @var bool */
    public $fail = false;

    /** @var string[] Hosts that were asked */
    public $requests = [];

    public function __construct(string $text = '')
    {
        $this->text = $text;
    }

    public function query(string $host, string $query): string
    {
        $this->requests[] = $host;
        if ($this->fail) {
            throw new ConnectionException('Fake WHOIS connection fault');
        }
        return $this->text;
    }
}
