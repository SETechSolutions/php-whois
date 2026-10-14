<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\DataObject;

/**
 * @property string $query
 * @property string $text
 * @property string $host
 * @property string $domain
 *
 * RDAP responses also carry 'source' => 'rdap' and 'httpStatus'. They are left out of
 * $dataDefault so toArray() and JSON output look the same as before.
 */
class TldResponse extends DataObject
{
    use TldResponseDeprected;

    /** @var string */
    protected $dataDefault = [
        'query' => '',
        'text' => '',
        'host' => '',
        'domain' => '',
    ];

    const SOURCE_WHOIS = 'whois';
    const SOURCE_RDAP = 'rdap';

    /**
     * Which protocol answered: 'whois' (text in $text) or 'rdap' (JSON in $text, $query is the URL).
     *
     * @return string
     */
    public function getSource()
    {
        return $this->get('source', self::SOURCE_WHOIS);
    }

    /**
     * HTTP status of an RDAP response, 0 for WHOIS.
     *
     * @return int
     */
    public function getHttpStatus()
    {
        return (int)$this->get('httpStatus', 0);
    }
}
