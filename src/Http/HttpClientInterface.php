<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Http;

use SETechSolutions\Whois\Exceptions\ConnectionException;

/**
 * Makes the HTTP GET requests RDAP needs. Implement it to use your own HTTP stack or to fake one in tests.
 */
interface HttpClientInterface
{
    /**
     * @param string $url
     * @return array ['status' => int, 'body' => string]. HTTP error statuses are returned, not thrown.
     * @throws ConnectionException When no HTTP response arrives
     */
    public function get(string $url): array;
}
