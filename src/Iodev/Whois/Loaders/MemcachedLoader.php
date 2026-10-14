<?php

declare(strict_types=1);

namespace Iodev\Whois\Loaders;

use Memcached;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Helpers\LoaderHelper;

class MemcachedLoader implements ILoader, IHttpLoader
{
    public function __construct(ILoader $l, Memcached $m, $keyPrefix = "", $ttl = 3600)
    {
        $this->loader = $l;
        $this->memcached = $m;
        $this->keyPrefix = $keyPrefix;
        $this->ttl = $ttl;
    }

    /** @var ILoader */
    private $loader;

    /** @var Memcached */
    private $memcached;

    /** @var string */
    private $keyPrefix;

    /** @var int */
    private $ttl;

    /**
     * @param string $whoisHost
     * @param string $query
     * @return string
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadText($whoisHost, $query)
    {
        $key = $this->keyPrefix . md5(serialize([$whoisHost, $query]));
        $val = $this->memcached->get($key);
        if ($val) {
            return unserialize($val);
        }
        $val = $this->loader->loadText($whoisHost, $query);
        $this->memcached->set($key, serialize($val), $this->ttl);
        return $val;
    }

    /**
     * @return ILoader
     */
    public function getLoader()
    {
        return $this->loader;
    }

    /**
     * Caches successful and "not found" responses; other errors are not cached.
     *
     * @param string $url
     * @return array ['status' => int, 'body' => string]
     * @throws ConnectionException
     */
    public function loadHttp($url)
    {
        $httpLoader = LoaderHelper::getHttpLoader($this->loader);
        if (!$httpLoader) {
            throw new ConnectionException('The wrapped loader does not support HTTP');
        }
        $key = $this->keyPrefix . md5(serialize(['http', $url]));
        $val = $this->memcached->get($key);
        if ($val) {
            return unserialize($val);
        }
        $val = $httpLoader->loadHttp($url);
        if (in_array($val['status'], [200, 404], true)) {
            $this->memcached->set($key, serialize($val), $this->ttl);
        }
        return $val;
    }
}
