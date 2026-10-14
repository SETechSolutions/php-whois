<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Fakes;

use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Http\HttpClientInterface;

class FakeHttpClient implements HttpClientInterface
{
    /** @var array url => ['status' => int, 'body' => string]; unknown URLs get a 404 */
    public $responses = [];

    /** @var bool */
    public $fail = false;

    /** @var string[] URLs that were requested */
    public $requests = [];

    public function __construct(array $responses = [])
    {
        $this->responses = $responses;
    }

    public function get(string $url): array
    {
        $this->requests[] = $url;
        if ($this->fail) {
            throw new ConnectionException('Fake HTTP connection fault');
        }
        return $this->responses[$url] ?? ['status' => 404, 'body' => ''];
    }
}
