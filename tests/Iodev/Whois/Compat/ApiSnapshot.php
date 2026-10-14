<?php

declare(strict_types=1);

namespace Iodev\Whois\Compat;

use ReflectionClass;
use ReflectionMethod;
use ReflectionParameter;
use ReflectionType;

/**
 * Describes the public and protected API of every class under src/Iodev/Whois,
 * so a release can be checked against the API of io-developer/php-whois 4.1.10.
 */
class ApiSnapshot
{
    /**
     * @param string $srcDir
     * @return array
     */
    public static function build($srcDir)
    {
        $classes = [];
        foreach (self::findClassNames($srcDir) as $className) {
            if (!class_exists($className) && !interface_exists($className) && !trait_exists($className)) {
                continue;
            }
            $classes[$className] = self::describeClass(new ReflectionClass($className));
        }
        ksort($classes);
        return $classes;
    }

    /**
     * @param string $srcDir
     * @return string[]
     */
    private static function findClassNames($srcDir)
    {
        $names = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($srcDir));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $rel = substr($file->getPathname(), strlen(rtrim($srcDir, '/')) + 1, -4);
            $names[] = 'Iodev\\Whois\\' . str_replace('/', '\\', $rel);
        }
        sort($names);
        return $names;
    }

    /**
     * @param ReflectionClass $c
     * @return array
     */
    private static function describeClass(ReflectionClass $c)
    {
        $kind = $c->isInterface() ? 'interface' : ($c->isTrait() ? 'trait' : 'class');
        $methods = [];
        foreach ($c->getMethods() as $m) {
            if ($m->isPrivate()) {
                continue;
            }
            $methods[$m->getName()] = self::describeMethod($m);
        }
        ksort($methods);
        $props = [];
        foreach ($c->getProperties() as $p) {
            if ($p->isPrivate()) {
                continue;
            }
            $props[$p->getName()] = [
                'visibility' => $p->isPublic() ? 'public' : 'protected',
                'static' => $p->isStatic(),
            ];
        }
        ksort($props);
        $consts = $c->getConstants();
        ksort($consts);
        $interfaces = $c->getInterfaceNames();
        sort($interfaces);
        return [
            'kind' => $kind,
            'abstract' => $kind === 'class' && $c->isAbstract(),
            'final' => $c->isFinal(),
            'parent' => $c->getParentClass() ? $c->getParentClass()->getName() : null,
            'interfaces' => $interfaces,
            'constants' => $consts,
            'properties' => $props,
            'methods' => $methods,
        ];
    }

    /**
     * @param ReflectionMethod $m
     * @return array
     */
    private static function describeMethod(ReflectionMethod $m)
    {
        $params = [];
        foreach ($m->getParameters() as $p) {
            $params[] = self::describeParam($p);
        }
        return [
            'visibility' => $m->isPublic() ? 'public' : 'protected',
            'static' => $m->isStatic(),
            'abstract' => $m->isAbstract(),
            'final' => $m->isFinal(),
            'return' => self::typeToString($m->getReturnType(), $m->getDeclaringClass()->getName()),
            'params' => $params,
        ];
    }

    /**
     * @param ReflectionParameter $p
     * @return array
     */
    private static function describeParam(ReflectionParameter $p)
    {
        $default = null;
        if ($p->isDefaultValueAvailable()) {
            $default = var_export($p->getDefaultValue(), true);
        }
        return [
            'name' => $p->getName(),
            'type' => self::typeToString($p->getType(), $p->getDeclaringClass()->getName()),
            'optional' => $p->isOptional(),
            'default' => $default,
            'byRef' => $p->isPassedByReference(),
            'variadic' => $p->isVariadic(),
        ];
    }

    /**
     * Same string on PHP 7.2 and 8.x: "?Name" for a nullable type, plain "mixed",
     * and "self" resolved to the class name.
     *
     * @param ReflectionType|null $type
     * @param string $selfClass
     * @return string|null
     */
    private static function typeToString($type, $selfClass)
    {
        if ($type === null) {
            return null;
        }
        $name = $type instanceof \ReflectionNamedType ? $type->getName() : (string)$type;
        $name = $name === 'self' ? $selfClass : $name;
        $nullable = $type->allowsNull() && $name !== 'mixed' && $name !== 'null';
        return ($nullable ? '?' : '') . $name;
    }

    /**
     * Lists every way $current breaks code written against $baseline.
     * Additions are allowed; removals and signature changes are not.
     *
     * @param array $baseline
     * @param array $current
     * @return string[]
     */
    public static function findBreaks(array $baseline, array $current)
    {
        $breaks = [];
        foreach ($baseline as $className => $old) {
            if (!isset($current[$className])) {
                $breaks[] = "$className: removed";
                continue;
            }
            $new = $current[$className];
            foreach (['kind', 'parent'] as $key) {
                if ($old[$key] !== $new[$key]) {
                    $breaks[] = "$className: $key changed from " . json_encode($old[$key]) . " to " . json_encode($new[$key]);
                }
            }
            if (!$old['final'] && $new['final']) {
                $breaks[] = "$className: became final";
            }
            if (!$old['abstract'] && $new['abstract']) {
                $breaks[] = "$className: became abstract";
            }
            foreach (array_diff($old['interfaces'], $new['interfaces']) as $iface) {
                // Built-in interfaces such as Stringable do not exist on PHP 7.
                if (!interface_exists($iface)) {
                    continue;
                }
                $breaks[] = "$className: no longer implements $iface";
            }
            foreach ($old['constants'] as $name => $value) {
                if (!array_key_exists($name, $new['constants'])) {
                    $breaks[] = "$className::$name: constant removed";
                } elseif ($new['constants'][$name] !== $value) {
                    $breaks[] = "$className::$name: constant value changed";
                }
            }
            foreach ($old['properties'] as $name => $prop) {
                if (!isset($new['properties'][$name])) {
                    $breaks[] = "$className::\$$name: property removed or made private";
                } elseif ($prop['visibility'] === 'public' && $new['properties'][$name]['visibility'] !== 'public') {
                    $breaks[] = "$className::\$$name: property no longer public";
                }
            }
            if ($old['kind'] === 'interface') {
                foreach (array_diff_key($new['methods'], $old['methods']) as $name => $m) {
                    $breaks[] = "$className::$name(): method added to an interface";
                }
            }
            foreach ($old['methods'] as $name => $oldMethod) {
                if (!isset($new['methods'][$name])) {
                    $breaks[] = "$className::$name(): removed";
                    continue;
                }
                foreach (self::findMethodBreaks($oldMethod, $new['methods'][$name]) as $msg) {
                    $breaks[] = "$className::$name(): $msg";
                }
            }
        }
        return $breaks;
    }

    /**
     * @param array $old
     * @param array $new
     * @return string[]
     */
    private static function findMethodBreaks(array $old, array $new)
    {
        $breaks = [];
        if ($old['visibility'] === 'public' && $new['visibility'] !== 'public') {
            $breaks[] = 'no longer public';
        }
        foreach (['static', 'abstract'] as $key) {
            if ($old[$key] !== $new[$key]) {
                $breaks[] = "$key changed";
            }
        }
        if (!$old['final'] && $new['final']) {
            $breaks[] = 'became final';
        }
        // Dropping a return type is fine: overrides that still declare it stay compatible.
        if ($new['return'] !== null && $new['return'] !== $old['return']) {
            $breaks[] = 'return type changed from ' . json_encode($old['return']) . ' to ' . json_encode($new['return']);
        }
        if ($old['params'] != $new['params']) {
            $breaks[] = 'parameters changed from ' . json_encode($old['params']) . ' to ' . json_encode($new['params']);
        }
        return $breaks;
    }
}
