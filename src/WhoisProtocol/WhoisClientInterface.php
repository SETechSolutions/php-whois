<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Exceptions\RateLimitException;

/**
 * Sends one query to a WHOIS server (TCP port 43) and returns the text it answers.
 * Implement it to route WHOIS traffic yourself or to fake a server in tests.
 */
interface WhoisClientInterface
{
    /**
     * @param string $host
     * @param string $query Including the line ending, e.g. "example.com\r\n"
     * @return string UTF-8 text
     * @throws ConnectionException
     * @throws RateLimitException
     */
    public function query(string $host, string $query): string;
}
