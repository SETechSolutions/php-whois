<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Iodev\Whois\Exceptions\ConnectionException;

class FakeHttpLoader implements ILoader, IHttpLoader
{
    /** @var string WHOIS text returned for every query */
    public $text = "";

    /** @var bool */
    public $failOnConnect = false;

    /** @var array url => ['status' => int, 'body' => string]; unknown URLs get a 404 */
    public $responses = [];

    /** @var bool */
    public $failOnHttp = false;

    /** @var string[] */
    public $whoisRequests = [];

    /** @var string[] */
    public $httpRequests = [];

    public function loadText($whoisHost, $query)
    {
        $this->whoisRequests[] = $whoisHost;
        if ($this->failOnConnect) {
            throw new ConnectionException("Fake connection fault");
        }
        return $this->text;
    }

    public function loadHttp($url)
    {
        $this->httpRequests[] = $url;
        if ($this->failOnHttp) {
            throw new ConnectionException("Fake HTTP connection fault");
        }
        return $this->responses[$url] ?? ['status' => 404, 'body' => ''];
    }
}
