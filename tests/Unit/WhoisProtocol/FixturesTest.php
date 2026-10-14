<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit\WhoisProtocol;

use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\DomainInfo;
use SETechSolutions\Whois\Mode;
use SETechSolutions\Whois\Tests\Fakes\FakeWhoisClient;
use SETechSolutions\Whois\Whois;

/**
 * Runs every recorded WHOIS answer in tests/fixtures/whois through a lookup and compares the
 * result with the expected values stored next to it.
 */
class FixturesTest extends TestCase
{
    const DIR = __DIR__ . '/../../fixtures/whois/';

    public function testRecordedWhoisAnswers()
    {
        $cases = require self::DIR . 'cases.php';
        $this->assertGreaterThan(300, count($cases));

        $errors = [];
        foreach ($cases as $case) {
            list ($domain, $textFile, $expectedFile) = $case;
            $whois = new Whois(['mode' => Mode::WHOIS_ONLY], null, new FakeWhoisClient(file_get_contents(self::DIR . $textFile)));
            $info = $whois->lookup($domain);

            if ($expectedFile === null) {
                if ($info !== null) {
                    $errors[] = "$textFile: a free domain was reported as registered";
                }
                continue;
            }
            if ($info === null) {
                $errors[] = "$textFile: a registered domain was reported as free";
                continue;
            }
            foreach (self::diff(self::expected($expectedFile), $info) as $field => $message) {
                $errors[] = "$textFile: $field $message";
            }
        }
        $this->assertSame([], $errors);
    }

    private static function expected(string $file): array
    {
        $expected = json_decode(file_get_contents(self::DIR . $file), true);
        if (!is_array($expected) || !$expected) {
            throw new \RuntimeException("Cannot read expected values from $file");
        }
        return array_replace([
            'domainName' => '',
            'whoisServer' => '',
            'nameServers' => [],
            'creationDate' => '',
            'expirationDate' => '',
            'updatedDate' => '',
            'states' => [],
            'owner' => '',
            'registrar' => '',
            'dnssec' => '',
        ], $expected);
    }

    /**
     * @return string[] field => description of the mismatch
     */
    private static function diff(array $expected, DomainInfo $info): array
    {
        $pairs = [
            'domain' => [$expected['domainName'], $info->domain()],
            'whoisServer' => [$expected['whoisServer'], $info->whoisServer()],
            'nameServers' => [self::sorted($expected['nameServers']), self::sorted($info->nameServers())],
            'createdAt' => [self::time($expected['creationDate']), self::timestamp($info->createdAt())],
            'expiresAt' => [self::time($expected['expirationDate']), self::timestamp($info->expiresAt())],
            'updatedAt' => [self::time($expected['updatedDate']), self::timestamp($info->updatedAt())],
            'statuses' => [self::sorted($expected['states']), self::sorted($info->statuses())],
            'owner' => [$expected['owner'], $info->owner()],
            'registrar' => [$expected['registrar'], $info->registrar()],
            'dnssec' => [$expected['dnssec'], $info->dnssec()],
        ];
        $diff = [];
        foreach ($pairs as $field => $pair) {
            if ($pair[0] != $pair[1]) {
                $diff[$field] = 'expected ' . json_encode($pair[0]) . ', got ' . json_encode($pair[1]);
            }
        }
        return $diff;
    }

    private static function sorted(array $values): array
    {
        sort($values);
        return $values;
    }

    /**
     * @param string|null $date "%Y" at the start stands for the current year
     */
    private static function time($date): int
    {
        $date = (string)$date;
        if (strpos($date, '%') !== false) {
            $date = preg_replace('~^%Y(-\d\d-\d\dT\d\d:\d\d)$~', date('Y') . '\1', $date);
        }
        return (int)strtotime($date);
    }

    /**
     * @param \DateTimeImmutable|null $date
     */
    private static function timestamp($date): int
    {
        return $date ? $date->getTimestamp() : 0;
    }
}
