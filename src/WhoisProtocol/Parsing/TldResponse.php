<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol\Parsing;

/**
 * A WHOIS server's answer, as the parsers receive it.
 *
 * @property string $query
 * @property string $text
 * @property string $host
 * @property string $domain
 *
 * @internal
 */
class TldResponse extends DataObject
{
    /** @var array */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
        'domain' => '',
    ];
}
