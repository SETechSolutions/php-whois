<?php

/*
 * Maintenance script for the bundled server lists. Review its output (and the git diff) before committing.
 *
 *   php bin/update-servers.php rdap             Download IANA's RDAP bootstrap file into resources/rdap-bootstrap.json
 *   php bin/update-servers.php check [--save file] [--load file] [--write]
 *       Query every WHOIS host in resources/whois-servers.json and report the ones that fail.
 *       Confirmed failures are: the hostname does not resolve, or the server says WHOIS was retired.
 *       Other failures are often rate limiting, because many hosts share one backend.
 *       --write fixes the confirmed ones: the host IANA lists now replaces the old one, or the entry is
 *       removed when the zone has RDAP. --save keeps the probe results as JSON and --load reuses them,
 *       so a run can be reviewed and then applied without querying every server again.
 *   php bin/update-servers.php missing [--write] Find root zone TLDs with no WHOIS server entry and look them up at
 *                                               whois.iana.org. --write adds them.
 */

declare(strict_types=1);

use SETechSolutions\Whois\Http\CurlHttpClient;
use SETechSolutions\Whois\Rdap\Bootstrap;
use SETechSolutions\Whois\WhoisProtocol\WhoisClient;

require __DIR__ . '/../vendor/autoload.php';

const RESOURCES_DIR = __DIR__ . '/../resources';
const SERVERS_FILE = RESOURCES_DIR . '/whois-servers.json';
const RDAP_FILE = RESOURCES_DIR . '/rdap-bootstrap.json';
const IANA_TLDS_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt';

/** Phrases registries put in WHOIS replies once they have switched WHOIS off */
const RETIRED_PATTERN = '~(service|whois)[^\n]{0,60}(discontinued|decommissioned|no longer (available|provided|supported)|has been (retired|shut ?down|turned off))|please use rdap~i';

/** Probe results that do not depend on rate limits */
const CONFIRMED_STATUSES = ['no-dns', 'retired'];

function main(array $argv): int
{
    $command = $argv[1] ?? '';
    $write = in_array('--write', $argv, true);
    switch ($command) {
        case 'rdap':
            return updateRdap();
        case 'check':
            return checkWhois($write, optionValue($argv, '--save'), optionValue($argv, '--load'));
        case 'missing':
            return addMissing($write);
    }
    fwrite(STDERR, "Usage: php bin/update-servers.php rdap | check [--save file] [--load file] [--write] | missing [--write]\n");
    return 1;
}

function optionValue(array $argv, string $name): string
{
    $i = array_search($name, $argv, true);
    return $i !== false && isset($argv[$i + 1]) ? $argv[$i + 1] : '';
}

function httpGet(string $url): string
{
    $result = (new CurlHttpClient(30))->get($url);
    if ($result['status'] !== 200) {
        throw new RuntimeException("HTTP {$result['status']} from $url");
    }
    return $result['body'];
}

function updateRdap(): int
{
    $data = json_decode(httpGet(Bootstrap::IANA_DNS_URL), true);
    if (!is_array($data) || empty($data['services'])) {
        fwrite(STDERR, "Unexpected bootstrap file\n");
        return 1;
    }
    $old = json_decode(file_get_contents(RDAP_FILE), true);
    $lines = [];
    foreach ($data['services'] as $service) {
        $line = json_encode($service, JSON_UNESCAPED_SLASHES);
        $lines[] = '    ' . str_replace(['","', '],['], ['", "', '], ['], $line);
    }
    $flags = JSON_UNESCAPED_SLASHES;
    $text = "{\n"
        . '  "description": ' . json_encode($data['description'] ?? '', $flags) . ",\n"
        . '  "publication": ' . json_encode($data['publication'] ?? '', $flags) . ",\n"
        . '  "version": ' . json_encode($data['version'] ?? '', $flags) . ",\n"
        . "  \"services\": [\n"
        . implode(",\n", $lines) . "\n"
        . "  ]\n}\n";
    file_put_contents(RDAP_FILE, $text);

    $count = function (array $d) {
        return array_sum(array_map(function ($s) { return count($s[0]); }, $d['services'] ?? []));
    };
    printf("RDAP bootstrap: %s -> %s, %d -> %d zones\n",
        $old['publication'] ?? '?', $data['publication'] ?? '?', $count($old ?: []), $count($data));
    return 0;
}

function loadServers(): array
{
    return json_decode(file_get_contents(SERVERS_FILE), true);
}

/**
 * @return array|null The entry on a line of the servers file, or null for other lines
 */
function parseServerLine(string $line)
{
    $entry = json_decode(rtrim(trim($line), ','), true);
    return is_array($entry) && isset($entry['zone'], $entry['host']) ? $entry : null;
}

/**
 * Edits the servers file line by line (it has one entry per line), so untouched entries keep their exact text.
 *
 * @param array $remove "zone host" => true
 * @param array $replace "zone host" => new host
 * @param array $add Entries to insert, each before the first entry of a later TLD
 * @return int[] Number of entries before and after
 */
function editServers(array $remove, array $replace, array $add): array
{
    $lines = file(SERVERS_FILE, FILE_IGNORE_NEW_LINES);
    // Entries that stay as they are. The file lists some zone and host pairs twice on purpose
    // (.ir, with two query formats), so only a replaced entry is ever dropped as a duplicate.
    $kept = [];
    foreach ($lines as $line) {
        $entry = parseServerLine($line);
        $key = $entry ? $entry['zone'] . ' ' . $entry['host'] : '';
        if ($entry && empty($remove[$key]) && !isset($replace[$key])) {
            $kept[$key] = true;
        }
    }
    $before = 0;
    $out = [];
    foreach ($lines as $line) {
        $entry = parseServerLine($line);
        if (!$entry) {
            $out[] = $line;
            continue;
        }
        $before++;
        $key = $entry['zone'] . ' ' . $entry['host'];
        if (!empty($remove[$key])) {
            continue;
        }
        if (isset($replace[$key])) {
            $newKey = $entry['zone'] . ' ' . $replace[$key];
            if (isset($kept[$newKey])) {
                continue;
            }
            $kept[$newKey] = true;
            $line = str_replace('"host": ' . json_encode($entry['host']), '"host": ' . json_encode($replace[$key]), $line);
        }
        $out[] = $line;
    }

    $tldOf = function (string $zone) {
        $labels = explode('.', $zone);
        return (string)end($labels);
    };
    foreach ($add as $entry) {
        $line = sprintf('  {"zone": %s, "host": %s},', json_encode($entry['zone']), json_encode($entry['host']));
        $pos = count($out) - 1;
        foreach ($out as $i => $other) {
            $otherEntry = parseServerLine($other);
            if ($otherEntry && $otherEntry['zone'] !== '.' && strcmp($tldOf($otherEntry['zone']), $tldOf($entry['zone'])) > 0) {
                $pos = $i;
                break;
            }
        }
        array_splice($out, $pos, 0, [$line]);
    }

    // Every entry ends with a comma except the last one
    $entryIndexes = array_keys(array_filter($out, 'parseServerLine'));
    $last = end($entryIndexes);
    foreach ($entryIndexes as $i) {
        $hasComma = substr(rtrim($out[$i]), -1) === ',';
        if ($i === $last && $hasComma) {
            $out[$i] = substr(rtrim($out[$i]), 0, -1);
        } elseif ($i !== $last && !$hasComma) {
            $out[$i] = rtrim($out[$i]) . ',';
        }
    }

    $text = implode("\n", $out) . "\n";
    $decoded = json_decode($text, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('The edited servers file is not valid JSON, nothing written');
    }
    file_put_contents(SERVERS_FILE, $text);
    return [$before, count($decoded)];
}

/**
 * Sends "nic.<tld>" to each host, many at a time, and returns host => [status, start of the reply].
 * Status is one of: ok, retired, no-dns, no-connect, timeout, no-reply.
 * Uses curl's telnet protocol; curl resolves and connects in parallel.
 */
function probeHosts(array $hostQueries, int $timeout = 15, int $parallel = 10): array
{
    $handleId = function ($ch) {
        return is_object($ch) ? spl_object_id($ch) : (int)$ch;
    };
    $results = [];
    $queue = $hostQueries;
    $active = [];
    $multi = curl_multi_init();
    while ($queue || $active) {
        while ($queue && count($active) < $parallel) {
            $host = (string)key($queue);
            $query = array_shift($queue);
            $input = fopen('php://temp', 'r+');
            fwrite($input, $query . "\r\n");
            rewind($input);
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => "telnet://$host:43",
                CURLOPT_PROTOCOLS => CURLPROTO_TELNET,
                CURLOPT_INFILE => $input,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_TIMEOUT => $timeout,
            ]);
            curl_multi_add_handle($multi, $ch);
            $active[$handleId($ch)] = ['host' => $host, 'input' => $input];
        }
        curl_multi_exec($multi, $running);
        curl_multi_select($multi, 1.0);
        while ($done = curl_multi_info_read($multi)) {
            $ch = $done['handle'];
            $id = $handleId($ch);
            $host = $active[$id]['host'];
            $text = (string)curl_multi_getcontent($ch);
            if ($text !== '') {
                // A timeout after some text is fine: a few servers keep the connection open
                $results[$host] = [preg_match(RETIRED_PATTERN, $text) ? 'retired' : 'ok', substr($text, 0, 300)];
            } elseif ($done['result'] === CURLE_COULDNT_RESOLVE_HOST) {
                $results[$host] = ['no-dns', ''];
            } elseif ($done['result'] === CURLE_COULDNT_CONNECT) {
                $results[$host] = ['no-connect', curl_error($ch)];
            } elseif ($done['result'] === CURLE_OPERATION_TIMEDOUT) {
                $results[$host] = ['timeout', ''];
            } else {
                $results[$host] = ['no-reply', curl_error($ch)];
            }
            curl_multi_remove_handle($multi, $ch);
            fclose($active[$id]['input']);
            unset($active[$id]);
            if (count($results) % 100 === 0) {
                fprintf(STDERR, "  %d done\n", count($results));
            }
        }
    }
    curl_multi_close($multi);
    return $results;
}

/**
 * The WHOIS host IANA lists for a TLD now, or '' when it lists none or cannot be asked.
 */
function ianaWhoisHost(string $tld): string
{
    static $cache = [];
    if (!isset($cache[$tld])) {
        try {
            $text = (new WhoisClient(15))->query('whois.iana.org', "$tld\r\n");
            $cache[$tld] = preg_match('~^whois:[ \t]*(\S+)~mi', $text, $m) ? strtolower($m[1]) : '';
        } catch (Exception $e) {
            fprintf(STDERR, "  whois.iana.org %s: %s\n", $tld, $e->getMessage());
            $cache[$tld] = '';
        }
    }
    return $cache[$tld];
}

function checkWhois(bool $write, string $saveFile, string $loadFile): int
{
    $servers = loadServers();
    $rdap = Bootstrap::fromIanaData(json_decode(file_get_contents(RDAP_FILE), true));
    if ($loadFile !== '') {
        $results = json_decode(file_get_contents($loadFile), true);
    } else {
        $hostQueries = [];
        foreach ($servers as $s) {
            if ($s['zone'] !== '.' && !isset($hostQueries[$s['host']])) {
                $tld = ltrim(str_replace('*.', '', $s['zone']), '.');
                $hostQueries[$s['host']] = "nic.$tld";
            }
        }
        fprintf(STDERR, "Probing %d WHOIS hosts...\n", count($hostQueries));
        $results = probeHosts($hostQueries);
    }
    if ($saveFile !== '') {
        file_put_contents($saveFile, json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    // What to do with each confirmed failure: a new host from IANA, or removal when RDAP covers the zone
    $replace = [];
    $remove = [];
    $report = [];
    foreach ($servers as $s) {
        if ($s['zone'] === '.') {
            continue;
        }
        list ($status, $detail) = $results[$s['host']] ?? ['ok', ''];
        if ($status === 'ok') {
            continue;
        }
        $key = $s['zone'] . ' ' . $s['host'];
        $hasRdap = (bool)$rdap->match('nic' . str_replace('*.', 'x.', $s['zone']));
        $action = '';
        if (in_array($status, CONFIRMED_STATUSES, true)) {
            $tld = ltrim($s['zone'], '.');
            $isTld = strpos($tld, '.') === false && strpos($tld, '*') === false;
            $ianaHost = $isTld ? ianaWhoisHost($tld) : '';
            if ($ianaHost !== '' && $ianaHost !== $s['host'] && !in_array($results[$ianaHost][0] ?? 'ok', CONFIRMED_STATUSES, true)) {
                $replace[$key] = $ianaHost;
                $action = "-> $ianaHost";
            } elseif ($hasRdap) {
                $remove[$key] = true;
                $action = 'remove';
            } else {
                $action = 'KEEP: no RDAP and no other host at IANA';
            }
        }
        $report[$status][] = sprintf("  %-28s %-36s %-7s %s %s", $s['zone'], $s['host'], $hasRdap ? 'rdap' : 'NO-RDAP',
            $action, $action === '' ? json_encode(trim(preg_replace('~\s+~', ' ', substr((string)$detail, 0, 80)))) : '');
    }
    ksort($report);
    foreach ($report as $status => $lines) {
        printf("%s (%d)%s:\n%s\n\n", $status, count($lines),
            in_array($status, CONFIRMED_STATUSES, true) ? '' : ', unconfirmed', implode("\n", $lines));
    }
    printf("%d entries failed. Confirmed (%s): %d get a new host from IANA, %d are removed because RDAP covers them.\n"
        . "The unconfirmed statuses are often rate limiting; check those hosts one at a time.\n",
        array_sum(array_map('count', $report)), implode(', ', CONFIRMED_STATUSES), count($replace), count($remove));

    if ($write && ($replace || $remove)) {
        list ($before, $after) = editServers($remove, $replace, []);
        printf("Wrote %s: %d entries -> %d\n", basename(SERVERS_FILE), $before, $after);
    }
    return 0;
}

function addMissing(bool $write): int
{
    $servers = loadServers();
    $known = [];
    foreach ($servers as $s) {
        $known[$s['zone']] = true;
    }
    $tlds = [];
    foreach (explode("\n", httpGet(IANA_TLDS_URL)) as $line) {
        $line = strtolower(trim($line));
        if ($line !== '' && $line[0] !== '#' && empty($known[".$line"])) {
            $tlds[] = $line;
        }
    }
    fprintf(STDERR, "%d root zone TLDs have no WHOIS entry, asking whois.iana.org...\n", count($tlds));

    $client = new WhoisClient(15);
    $added = [];
    $noWhois = [];
    $skipped = [];
    foreach ($tlds as $tld) {
        try {
            $text = $client->query('whois.iana.org', "$tld\r\n");
        } catch (Exception $e) {
            fprintf(STDERR, "  %s: %s\n", $tld, $e->getMessage());
            continue;
        }
        if (!preg_match('~^whois:[ \t]*(\S+)~mi', $text, $m)) {
            $noWhois[] = $tld;
            continue;
        }
        $host = strtolower($m[1]);
        // IANA still lists some hosts that are gone; do not add what "check" would remove again
        $dead = '';
        if (!gethostbynamel($host)) {
            $dead = 'does not resolve';
        } else {
            try {
                $dead = preg_match(RETIRED_PATTERN, $client->query($host, "nic.$tld\r\n")) ? 'WHOIS retired' : '';
            } catch (Exception $e) {
                // Not confirmed dead: could be a rate limit or a slow server
            }
        }
        if ($dead !== '') {
            $skipped[] = $tld;
            printf("  .%-24s %-36s skipped: %s\n", $tld, $host, $dead);
            continue;
        }
        $added[] = ['zone' => ".$tld", 'host' => $host];
        printf("  .%-24s %s\n", $tld, $host);
    }
    printf("%d TLDs have a WHOIS server to add; %d have a dead one listed at IANA; %d have none listed\n",
        count($added), count($skipped), count($noWhois));

    if ($write && $added) {
        list ($before, $after) = editServers([], [], $added);
        printf("Wrote %s: %d entries -> %d\n", basename(SERVERS_FILE), $before, $after);
    }
    return 0;
}

exit(main($argv));
