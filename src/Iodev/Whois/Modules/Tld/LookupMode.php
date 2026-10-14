<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

/**
 * Which protocols TldModule uses for domain lookups, and in what order.
 * A protocol is skipped when it has no server for the domain's zone.
 */
class LookupMode
{
    /** RDAP first, WHOIS if RDAP fails. lookupDomain() still asks WHOIS first for raw text. The default. */
    const RDAP_FIRST = 'rdapFirst';

    /** WHOIS first, RDAP if WHOIS fails */
    const WHOIS_FIRST = 'whoisFirst';

    /** RDAP only */
    const RDAP_ONLY = 'rdapOnly';

    /** WHOIS only, the behaviour of io-developer/php-whois 4.1 */
    const WHOIS_ONLY = 'whoisOnly';

    /**
     * @return string[]
     */
    public static function all()
    {
        return [self::RDAP_FIRST, self::WHOIS_FIRST, self::RDAP_ONLY, self::WHOIS_ONLY];
    }
}
