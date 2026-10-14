<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \SETechSolutions\Whois\DomainInfo|null lookup(string $domain)
 * @method static bool isAvailable(string $domain)
 * @method static \SETechSolutions\Whois\RawResponse raw(string $domain)
 * @method static array options()
 *
 * @see \SETechSolutions\Whois\Whois
 */
class Whois extends Facade
{
    protected static function getFacadeAccessor()
    {
        return \SETechSolutions\Whois\Whois::class;
    }
}
