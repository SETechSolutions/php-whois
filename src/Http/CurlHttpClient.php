<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Http;

use SETechSolutions\Whois\Exceptions\ConnectionException;

class CurlHttpClient implements HttpClientInterface
{
    /** @var int */
    private $timeout;

    /** @var array */
    private $curlOptions;

    /**
     * @param int $timeout Seconds
     * @param array $curlOptions Extra curl options, e.g. a proxy. The request's own options override them.
     */
    public function __construct(int $timeout = 30, array $curlOptions = [])
    {
        $this->timeout = max(1, $timeout);
        $this->curlOptions = $curlOptions;
    }

    public function get(string $url): array
    {
        $curl = curl_init();
        if (!$curl) {
            throw new ConnectionException('Curl not created');
        }
        curl_setopt_array($curl, array_replace($this->curlOptions, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => min($this->timeout, 15),
            CURLOPT_USERAGENT => 'setechsolutions/php-whois (+https://github.com/SETechSolutions/php-whois)',
            CURLOPT_HTTPHEADER => ['Accept: application/rdap+json, application/json'],
        ]));
        $body = curl_exec($curl);
        $error = curl_error($curl);
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
            throw new ConnectionException($error, $errno);
        }
        return ['status' => $status, 'body' => (string)$body];
    }
}
