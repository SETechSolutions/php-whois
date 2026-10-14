<?php

declare(strict_types=1);

namespace SETechSolutions\Whois;

/**
 * Which protocols a lookup uses, and in what order.
 * A protocol is skipped when it has no server for the domain's zone.
 */
class Mode
{
    /** RDAP first, WHOIS if RDAP fails. raw() still asks WHOIS first, for plain text. The default. */
    const RDAP_FIRST = 'rdap_first';

    /** WHOIS first, RDAP if WHOIS fails */
    const WHOIS_FIRST = 'whois_first';

    /** RDAP only */
    const RDAP_ONLY = 'rdap_only';

    /** WHOIS only */
    const WHOIS_ONLY = 'whois_only';

    /**
     * @return string[]
     */
    public static function all(): array
    {
        return [self::RDAP_FIRST, self::WHOIS_FIRST, self::RDAP_ONLY, self::WHOIS_ONLY];
    }
}
