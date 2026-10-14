<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;

trait CurlHttpTrait
{
    /**
     * @param string $url
     * @param int $timeout
     * @param array $options Extra curl options (proxy etc.), the request options below override them
     * @return array ['status' => int, 'body' => string]
     * @throws ConnectionException
     */
    protected function loadHttpWithCurl($url, $timeout, array $options = [])
    {
        $curl = curl_init();
        if (!$curl) {
            throw new ConnectionException('Curl not created');
        }
        curl_setopt_array($curl, array_replace($options, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout > 0 ? min($timeout, 15) : 15,
            CURLOPT_USERAGENT => 'setechsolutions/php-whois (+https://github.com/SETechSolutions/php-whois)',
            CURLOPT_HTTPHEADER => ['Accept: application/rdap+json, application/json'],
        ]));
        $body = curl_exec($curl);
        $errstr = curl_error($curl);
        $errno = curl_errno($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if (PHP_VERSION_ID < 80000) {
            curl_close($curl); // a no-op since PHP 8.0, deprecated in 8.5
        }

        if ($body === false) {
            // Some servers (e.g. Verisign) drop the TLS connection right after a 404 header.
            // The status is all that matters for an error response, so keep it.
            if ($status >= 400) {
                return ['status' => $status, 'body' => ''];
            }
            throw new ConnectionException($errstr, $errno);
        }
        return ['status' => $status, 'body' => (string)$body];
    }
}
