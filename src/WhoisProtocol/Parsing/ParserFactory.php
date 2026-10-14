<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\WhoisProtocol\Parsing;

use SETechSolutions\Whois\Resources;

/**
 * Builds the WHOIS text parsers from the parser config files in resources/.
 *
 * @internal
 */
class ParserFactory
{
    /**
     * @param string|null $type One of the TldParser type constants, auto by default
     */
    public static function create($type = null): TldParser
    {
        $type = $type ?: TldParser::AUTO;
        $classes = [
            TldParser::AUTO => AutoParser::class,
            TldParser::COMMON => CommonParser::class,
            TldParser::COMMON_FLAT => CommonParser::class,
            TldParser::BLOCK => BlockParser::class,
            TldParser::INDENT => IndentParser::class,
            TldParser::INDENT_AUTOFIX => IndentParser::class,
        ];
        if (!isset($classes[$type])) {
            throw new \InvalidArgumentException("Unknown parser type '$type'");
        }
        return self::createByClass($classes[$type], $type);
    }

    /**
     * @param string $className
     * @param string|null $configType
     */
    public static function createByClass(string $className, $configType = null): TldParser
    {
        $config = self::configByType($configType ?: TldParser::AUTO);
        /* @var $parser TldParser */
        $parser = new $className();
        $parser->setConfig($config);
        if ($parser instanceof AutoParser) {
            foreach ($config['parserTypes'] ?? [] as $type) {
                $parser->addParser(self::create($type));
            }
        }
        return $parser;
    }

    /**
     * The parser a server entry asks for (keys parserClass, parserType, parserOptions).
     */
    public static function forServerConfig(array $config, ?TldParser $default = null): TldParser
    {
        $options = $config['parserOptions'] ?? [];
        if (isset($config['parserClass'])) {
            return self::createByClass($config['parserClass'], $config['parserType'] ?? null)->setOptions($options);
        }
        if (isset($config['parserType'])) {
            return self::create($config['parserType'])->setOptions($options);
        }
        return $default ?: self::create()->setOptions($options);
    }

    private static function configByType(string $type): array
    {
        $extra = [];
        if ($type === TldParser::COMMON_FLAT) {
            $type = TldParser::COMMON;
            $extra = ['isFlat' => true];
        }
        if ($type === TldParser::INDENT_AUTOFIX) {
            $type = TldParser::INDENT;
            $extra = ['isAutofix' => true];
        }
        return array_merge(Resources::load("parser.$type"), $extra);
    }
}
