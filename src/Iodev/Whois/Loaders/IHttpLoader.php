<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;

/**
 * A loader that can also make HTTP GET requests, which RDAP lookups need.
 * Kept apart from ILoader so existing ILoader implementations keep working (they stay WHOIS-only).
 */
interface IHttpLoader
{
    /**
     * @param string $url
     * @return array ['status' => int, 'body' => string]
     * @throws ConnectionException
     */
    function loadHttp($url);
}
