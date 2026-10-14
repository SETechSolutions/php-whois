<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Exceptions\RateLimitException;
use SETechSolutions\Whois\WhoisProtocol\Parsing\TextHelper;

/**
 * Talks to WHOIS servers over a plain socket, or through curl when curl options
 * (such as a proxy) are given.
 */
class WhoisClient implements WhoisClientInterface
{
    /** @var int */
    private $timeout;

    /** @var array */
    private $curlOptions;

    /**
     * @param int $timeout Seconds
     * @param array $curlOptions When not empty, queries go through curl with these options
     */
    public function __construct(int $timeout = 30, array $curlOptions = [])
    {
        $this->timeout = max(1, $timeout);
        $this->curlOptions = $curlOptions;
    }

    public function query(string $host, string $query): string
    {
        $text = $this->curlOptions ? $this->queryWithCurl($host, $query) : $this->queryWithSocket($host, $query);
        $text = TextHelper::toUtf8($text);
        if (preg_match('~^WHOIS\s+.*?LIMIT\s+EXCEEDED~ui', $text, $m)) {
            throw new RateLimitException($m[0] . ": $host");
        }
        return $text;
    }

    private function queryWithSocket(string $host, string $query): string
    {
        if (!$this->resolves($host)) {
            throw new ConnectionException("Host is unreachable: $host");
        }
        $errno = null;
        $errstr = null;
        $handle = @fsockopen($host, 43, $errno, $errstr, $this->timeout);
        if (!$handle) {
            throw new ConnectionException((string)$errstr ?: "Cannot connect to $host", (int)$errno);
        }
        stream_set_timeout($handle, $this->timeout);
        if (false === fwrite($handle, $query)) {
            fclose($handle);
            throw new ConnectionException("Query cannot be written: $host");
        }
        $text = '';
        while (!feof($handle)) {
            $chunk = fread($handle, 8192);
            if (false === $chunk || stream_get_meta_data($handle)['timed_out']) {
                fclose($handle);
                throw new ConnectionException("Response cannot be read: $host");
            }
            $text .= $chunk;
        }
        fclose($handle);
        return $text;
    }

    private function queryWithCurl(string $host, string $query): string
    {
        $input = fopen('php://temp', 'r+');
        if (!$input) {
            throw new ConnectionException('Query stream not created');
        }
        fwrite($input, $query);
        rewind($input);
        $curl = curl_init();
        if (!$curl) {
            fclose($input);
            throw new ConnectionException('Curl not created');
        }
        curl_setopt_array($curl, array_replace($this->curlOptions, [
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROTOCOLS => CURLPROTO_TELNET,
            CURLOPT_URL => "telnet://$host:43",
            CURLOPT_INFILE => $input,
        ]));
        $result = curl_exec($curl);
        $error = curl_error($curl);
        $errno = curl_errno($curl);
        if (PHP_VERSION_ID < 80000) {
            curl_close($curl); // a no-op since PHP 8.0, deprecated in 8.5
        }
        fclose($input);
        if ($result === false) {
            throw new ConnectionException($error, $errno);
        }
        return (string)$result;
    }

    /**
     * A failed DNS lookup would otherwise block for the system resolver's own, much longer, timeout.
     */
    private function resolves(string $host): bool
    {
        $original = getenv('RES_OPTIONS');
        putenv("RES_OPTIONS=retrans:1 retry:1 timeout:{$this->timeout} attempts:1");
        $resolved = (bool)gethostbynamel($host);
        $original === false ? putenv('RES_OPTIONS') : putenv("RES_OPTIONS=$original");
        return $resolved;
    }
}
