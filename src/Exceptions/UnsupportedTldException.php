<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Exceptions;

/**
 * No RDAP or WHOIS server is known for the domain's zone (under the lookup mode in use).
 */
class UnsupportedTldException extends WhoisException
{
}
