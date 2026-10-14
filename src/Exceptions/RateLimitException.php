<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Exceptions;

/**
 * The server refused the query because too many were sent.
 */
class RateLimitException extends WhoisException
{
}
