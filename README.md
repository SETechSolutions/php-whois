# PHP WHOIS

[![PHP version](https://img.shields.io/badge/php-%3E%3D7.2.5-8892BF.svg)](https://www.php.net/)
[![Laravel](https://img.shields.io/badge/laravel-6%20to%2013-FF2D20.svg)](https://laravel.com/)
[![Packagist](https://img.shields.io/packagist/v/setechsolutions/php-whois.svg)](https://packagist.org/packages/setechsolutions/php-whois)
[![tests](https://github.com/SETechSolutions/php-whois/actions/workflows/tests.yml/badge.svg)](https://github.com/SETechSolutions/php-whois/actions/workflows/tests.yml)

Looks up domain registration data: registrar, creation and expiry dates, name servers, status,
and whether a domain is free. It asks **RDAP first and falls back to WHOIS**, and returns the same
result object either way. Works in plain PHP and in Laravel 6 to 13.

Why both protocols: since 28 January 2025 ICANN no longer requires gTLD registries and registrars
to run WHOIS, and RDAP is the authoritative source for them. Most country-code domains
(.de, .il, .ru, ...) still have WHOIS and no RDAP.

> Looking for the drop-in replacement of io-developer/php-whois with the old `Iodev\Whois` classes?
> That is version 4: `composer require setechsolutions/php-whois:^4.2`.
> See the [4.x branch](https://github.com/SETechSolutions/php-whois/tree/4.x).

## Installation

```
composer require setechsolutions/php-whois
```

Requirements: PHP 7.2.5 or newer with the `curl`, `mbstring` and `json` extensions, and outgoing
access to port 443 (RDAP) and port 43 (WHOIS).

## Usage

```php
use SETechSolutions\Whois\Whois;

$whois = new Whois();

$info = $whois->lookup('example.com');     // DomainInfo, or null when the domain is not registered

if ($info) {
    echo $info->registrar();                    // "RESERVED-Internet Assigned Numbers Authority"
    echo $info->expiresAt()->format('Y-m-d');   // DateTimeImmutable, or null if not published
    print_r($info->nameServers());              // ["elliott.ns.cloudflare.com", ...]
    echo $info->source();                       // "rdap" or "whois"
}

$whois->isAvailable('some-free-name.com');  // true

echo $whois->raw('example.com')->text();    // the server's own answer, unparsed
```

International names work as they are: `$whois->lookup('münchen.de')`.

### Laravel

Nothing to register: Laravel finds the service provider and the `Whois` facade by itself.

```php
use Whois;

$info = Whois::lookup('example.com');

Route::get('/domains/{domain}', function ($domain) {
    return response()->json(Whois::lookup($domain));
});
```

The client can also be injected:

```php
use SETechSolutions\Whois\Whois;

public function show(Whois $whois, $domain)
{
    return view('domain', ['available' => $whois->isAvailable($domain)]);
}
```

To change the settings, publish the config file:

```
php artisan vendor:publish --tag=whois-config
```

`config/whois.php` holds the options described below. The two most common ones can also be set
in `.env`: `WHOIS_MODE=whois_first` and `WHOIS_TIMEOUT=10`.

## The result

`lookup()` returns a `SETechSolutions\Whois\DomainInfo`:

| Method | Returns |
|---|---|
| `domain()` | The name in ASCII, lowercase (`xn--mnchen-3ya.de`) |
| `unicodeDomain()` | The name with international characters (`münchen.de`) |
| `registrar()` | Registrar name |
| `owner()` | Registrant organization or name. Often empty: registries hide it for privacy |
| `createdAt()`, `updatedAt()`, `expiresAt()` | `DateTimeImmutable` in UTC, or `null` |
| `nameServers()` | List of host names, lowercase |
| `statuses()` | List of status codes, lowercase: `ok`, `clienttransferprohibited`, ... |
| `dnssec()` | As the registry states it: `unsigned`, `signedDelegation`, ... |
| `whoisServer()` | The registrar's or registry's WHOIS server, when named |
| `source()` | `rdap` or `whois` |
| `raw()` | The `RawResponse` the data was read from: `text()`, `source()`, `server()`, `query()` |
| `toArray()` | All of the above except `raw()`, with dates as ISO 8601 strings |

A field the registry does not publish is empty: `''`, `[]` or `null`. `DomainInfo` is
JSON-serializable, so it can be returned from a Laravel route or passed to `json_encode()`.

## Options

Pass them to the constructor, or set them in `config/whois.php` in Laravel:

```php
$whois = new Whois([
    'mode' => 'whois_first',
    'timeout' => 10,
]);
```

| Option | Default | Meaning |
|---|---|---|
| `mode` | `rdap_first` | Which protocols are used, see below |
| `timeout` | `30` | Seconds to wait for each request |
| `follow_registrar` | `true` | Registries such as .com link to the registrar's RDAP server, which usually knows the owner. `true` makes a second request to fetch that |
| `curl_options` | `[]` | Extra curl options for every request, for example a proxy |
| `rdap_servers` | `[]` | RDAP servers to add: `['example' => 'https://rdap.nic.example/']` |
| `whois_servers` | `[]` | WHOIS servers to try before the bundled ones: `[['zone' => '.example', 'host' => 'whois.nic.example']]` |

### Modes

| Mode | `lookup()`, `isAvailable()` | `raw()` |
|---|---|---|
| `rdap_first` (default) | RDAP, then WHOIS if RDAP fails | WHOIS text, then RDAP JSON if WHOIS fails |
| `whois_first` | WHOIS, then RDAP if WHOIS fails | same |
| `rdap_only` | RDAP | RDAP JSON |
| `whois_only` | WHOIS | WHOIS text |

The constants are in `SETechSolutions\Whois\Mode`. "Fails" means a connection error, a server
error or a rate limit. "Domain not found" is an answer, not a failure, so it does not trigger the
second protocol. A zone that has a server for only one protocol uses that protocol in the two
"first" modes.

If outgoing HTTPS is blocked and only port 43 is open, use `whois_only`. Otherwise every lookup
first waits for the HTTPS connection to fail.

### Proxy

```php
$whois = new Whois([
    'curl_options' => [
        CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5,
        CURLOPT_PROXY => '127.0.0.1:1080',
    ],
]);
```

When `curl_options` is set, WHOIS queries go through curl as well, so the proxy covers both protocols.

## Errors

Every exception extends `SETechSolutions\Whois\Exceptions\WhoisException`:

| Exception | When |
|---|---|
| `InvalidDomainException` | The input is not a domain name |
| `UnsupportedTldException` | No server is known for the zone (in the mode in use) |
| `ConnectionException` | The server could not be reached, timed out or had a server error |
| `RateLimitException` | The server refused the query because too many were sent |

```php
use SETechSolutions\Whois\Exceptions\RateLimitException;
use SETechSolutions\Whois\Exceptions\WhoisException;

try {
    $info = $whois->lookup($domain);
} catch (RateLimitException $e) {
    // try again later
} catch (WhoisException $e) {
    // anything else
}
```

Registries limit how many queries they accept. If you look the same domains up repeatedly,
cache the results.

## Supported versions

| | Versions |
|---|---|
| PHP | 7.2.5 to 8.5 |
| Laravel | 6, 7, 8, 9, 10, 11, 12, 13 (optional: the package has no Laravel dependency) |

Each Laravel version is tested on the lowest and the highest PHP version it runs on.

Note for Laravel 11 and older: these Laravel releases have open security advisories, and
Composer 2.10 refuses to install packages with advisories unless told otherwise. That affects any
`composer update` in such a project, with or without this package.

## Development

No local PHP setup is needed, the scripts run in Docker:

| Command | What it runs |
|---|---|
| `bin/docker-test 8.3` | Unit tests on PHP 8.3 |
| `bin/docker-test 8.3 12` | Unit tests, then the Laravel tests against Laravel 12 |
| `bin/docker-test 8.3 - live` | The tests that query real servers |
| `bin/test-laravel-app 8.4 12` | Creates a fresh Laravel 12 app, installs this checkout and runs real lookups in it |
| `bin/test-laravel-app all` | The same for Laravel 6 to 13 |

With PHP installed locally: `composer test`, and `composer test-live` for the live tests. The
Laravel tests need `orchestra/testbench` for the Laravel version to test, which is not in
`composer.json` because each Laravel version needs a different one.

The server lists in `resources/` are maintained with `bin/update-servers` (`rdap`, `check`, `missing`).

## Credits

The WHOIS text parsers and their test data come from
[io-developer/php-whois](https://github.com/io-developer/php-whois) by Sergey Sedyshev and its
contributors (MIT).
