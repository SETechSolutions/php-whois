<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol\Parsing;

/**
 * @internal
 */
class TextHelper
{
    /**
     * @param string $text
     * @return string
     */
    public static function toUtf8($text)
    {
        // Strict: since PHP 8.0 a loose check reports Latin-1 text as ASCII and the conversion destroys it
        $srcEncoding = mb_detect_encoding($text, mb_detect_order(), true);
        if (!empty($srcEncoding) && strtolower($srcEncoding) !== 'utf-8') {
            return mb_convert_encoding($text, 'utf-8', strtolower($srcEncoding));
        }
        if (mb_check_encoding($text, 'utf-8')) {
            return $text;
        }
        if (mb_check_encoding($text, 'windows-1252')) {
            return mb_convert_encoding($text, 'utf-8', 'windows-1252');
        }
        if (mb_check_encoding($text, 'windows-1251')) {
            return mb_convert_encoding($text, 'utf-8', 'windows-1251');
        }
        return $text;
    }
}
