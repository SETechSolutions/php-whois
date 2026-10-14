<?php

declare(strict_types=1);

namespace SETechSolutions\Whois;

/**
 * Reads the JSON data files shipped in resources/.
 *
 * @internal
 */
class Resources
{
    /** @var array */
    private static $cache = [];

    /**
     * @param string $name File name without ".json"
     * @return array
     */
    public static function load(string $name): array
    {
        if (!isset(self::$cache[$name])) {
            $json = file_get_contents(__DIR__ . '/../resources/' . $name . '.json');
            self::$cache[$name] = (array)json_decode((string)$json, true);
        }
        return self::$cache[$name];
    }
}
