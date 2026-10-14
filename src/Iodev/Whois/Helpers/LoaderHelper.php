<?php

declare(strict_types=1);

namespace Iodev\Whois\Helpers;

use Iodev\Whois\Loaders\IHttpLoader;
use Iodev\Whois\Loaders\MemcachedLoader;
use ReflectionMethod;

class LoaderHelper
{
    /**
     * Returns the loader if RDAP requests may be sent through it, otherwise null.
     *
     * A subclass that replaces loadText() but not loadHttp(), such as a test fake built on
     * SocketLoader, stays WHOIS-only. Otherwise it would start making real HTTP requests.
     *
     * @param mixed $loader
     * @return IHttpLoader|null
     */
    public static function getHttpLoader($loader)
    {
        if (!$loader instanceof IHttpLoader) {
            return null;
        }
        if ($loader instanceof MemcachedLoader) {
            return self::getHttpLoader($loader->getLoader()) ? $loader : null;
        }
        if (!method_exists($loader, 'loadText')) {
            return $loader;
        }
        $textClass = (new ReflectionMethod($loader, 'loadText'))->getDeclaringClass()->getName();
        $httpClass = (new ReflectionMethod($loader, 'loadHttp'))->getDeclaringClass()->getName();
        if ($textClass === $httpClass || is_subclass_of($httpClass, $textClass)) {
            return $loader;
        }
        return null;
    }
}
