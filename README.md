# PHP WHOIS

[![PHP version](https://img.shields.io/badge/php-%3E%3D7.2-8892BF.svg)](https://secure.php.net/)
[![Packagist](https://img.shields.io/packagist/v/setechsolutions/php-whois.svg)](https://packagist.org/packages/setechsolutions/php-whois)
[![tests](https://github.com/SETechSolutions/php-whois/actions/workflows/tests.yml/badge.svg)](https://github.com/SETechSolutions/php-whois/actions/workflows/tests.yml)

A drop-in replacement for [io-developer/php-whois](https://github.com/io-developer/php-whois) that
looks domains up over **RDAP first and falls back to WHOIS**. Same `Iodev\Whois` classes, same methods,
same result objects.

Why: since 28 January 2025 ICANN no longer requires gTLD registries and registrars to run WHOIS, and
RDAP is the authoritative source. The original library has had no release since January 2023 and speaks
WHOIS only. Most country-code domains (.de, .il, .ru, ...) still have WHOIS and no RDAP, so this
library speaks both.

## Use case
 * Raw and parsed domain lookup over RDAP and WHOIS
 * Raw and parsed ASN routes lookup
 * Direct queries to TLD/ASN hosts
 * Extending and customizing the default hosts, parsers, etc.
 * Proxying via CurlLoader

## Migrating from io-developer/php-whois

Change one line in `composer.json` and run `composer update`:
````diff
-    "io-developer/php-whois": "^4.0"
+    "setechsolutions/php-whois": "^4.2"
````
No code changes are needed. The package declares that it replaces `io-developer/php-whois`, so
packages that depend on the original (for example `larva/laravel-whois`) keep working.

What behaves differently after the switch:

* `loadDomainInfo()` and `isDomainAvailable()` ask RDAP first for zones that have an RDAP server.
  The result is the same `TldInfo` with the same fields in the same formats. `$info->parserType` is
  `rdap`, `$info->getResponse()->text` is JSON, and `$info->getExtra()` holds the decoded JSON under
  `rdap` instead of the WHOIS parser's `groups`.
* `$info->owner` is more often empty: RDAP redacts registrant data more strictly than WHOIS did.
* RDAP needs outgoing HTTPS (port 443). If only port 43 is open, set the mode to `whoisOnly` (see below);
  otherwise every lookup first waits for the HTTPS connection to fail.
* `lookupDomain()` still returns WHOIS text whenever a WHOIS server answers.
* A loader of your own (any `ILoader`, or a subclass of `SocketLoader` / `CurlLoader` that overrides
  `loadText()`) is used for WHOIS only, exactly as before. See "RDAP with a custom loader".

To get the old behaviour back completely: `$whois->setLookupMode(LookupMode::WHOIS_ONLY);`

Fixed along the way, all present in io-developer/php-whois 4.1.10:

* PHP 8.4+ printed a deprecation for every "implicitly nullable parameter" (17 places).
* PHP 8.2+ printed "Creation of dynamic property" for custom parser classes.
* PHP 8.5 printed a deprecation for `curl_close()` in `CurlLoader`.
* PHP 8.x turned non-UTF-8 replies into question marks (for example `ä` in .fi replies).
* PHP 7.x threw a `TypeError` on `json_encode($info)`.

## Installation

##### System requirements:
* PHP >= __7.2__, tested up to __8.5__
* php-curl
* php-mbstring
* Outgoing port __443__ (RDAP) and port __43__ (WHOIS) open in firewall

Optional:
* php-intl
* php-memcached + Memcached server

##### Project requirements:
* PSR-4 autoloader

##### Composer:
````
composer require setechsolutions/php-whois
````
or composer.json:
````
"require": {
    "setechsolutions/php-whois": "^4.2"
}
````


## Usage

### Domain lookup

##### How to get summary about domain:
```php
<?php

use Iodev\Whois\Factory;

// Creating default configured client
$whois = Factory::get()->createWhois();

// Checking availability
if ($whois->isDomainAvailable("google.com")) {
    print "Bingo! Domain is available! :)";
}

// Supports Unicode (converts to punycode)
if ($whois->isDomainAvailable("почта.рф")) {
    print "Bingo! Domain is available! :)";
}

// Getting raw-text lookup
$response = $whois->lookupDomain("google.com");
print $response->text;

// Getting parsed domain info
$info = $whois->loadDomainInfo("google.com");
print_r([
    'Domain created' => date("Y-m-d", $info->creationDate),
    'Domain expires' => date("Y-m-d", $info->expirationDate),
    'Domain owner' => $info->owner,
    'Answered by' => $info->getResponse()->getSource(), // "rdap" or "whois"
]);

```

##### RDAP or WHOIS: lookup modes
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\LookupMode;

$whois = Factory::get()->createWhois();
$whois->setLookupMode(LookupMode::WHOIS_FIRST);
```

| Mode | `loadDomainInfo()`, `isDomainAvailable()` | `lookupDomain()` |
|---|---|---|
| `LookupMode::RDAP_FIRST` (default) | RDAP, then WHOIS if RDAP fails | WHOIS text, then RDAP JSON if WHOIS fails |
| `LookupMode::WHOIS_FIRST` | WHOIS, then RDAP if WHOIS fails | same |
| `LookupMode::RDAP_ONLY` | RDAP | RDAP JSON |
| `LookupMode::WHOIS_ONLY` | WHOIS, as in io-developer/php-whois | WHOIS text |

"Fails" means a connection error, a server error or a rate limit (HTTP 429). "Domain not found" is an
answer, not a failure, so it does not trigger the second protocol. A zone that has a server for only
one protocol uses that protocol in the two "first" modes. `ServerMismatchException` is thrown when no
allowed protocol has a server for the zone.

The RDAP servers come from a snapshot of [IANA's bootstrap file](https://data.iana.org/rdap/dns.json)
shipped with the package. For registries that link to the registrar's RDAP server (.com, .net and
others) a second request fetches the registrar's record, which usually adds the owner and the
registrar's WHOIS server. Turn that off with `$whois->getTldModule()->setRdapFollowRelated(false)`.

##### RDAP servers customization:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Modules\Tld\Rdap\RdapBootstrap;

$whois = Factory::get()->createWhois();
$tld = $whois->getTldModule();

// Add or replace the RDAP server of a zone
$tld->getRdapBootstrap()->addServers([
    'custom' => 'https://rdap.nic.custom/',
]);

// Or use IANA's current list instead of the bundled snapshot.
// Cache it: IANA asks clients to fetch the file at most once a day.
$tld->setRdapBootstrap(RdapBootstrap::loadFromIana(new SocketLoader()));
```

##### RDAP with a custom loader:
RDAP requests go through the loader when it implements `Iodev\Whois\Loaders\IHttpLoader`
(`SocketLoader`, `CurlLoader` and `MemcachedLoader` do). A loader that does not, or a subclass that
overrides `loadText()` without `loadHttp()`, stays WHOIS-only, so existing custom loaders and test
fakes never start making HTTP requests. To give such a loader RDAP, implement `loadHttp($url)` in it or
set a separate one:
```php
<?php

use Iodev\Whois\Loaders\SocketLoader;

$whois->getTldModule()->setHttpLoader(new SocketLoader());
```

##### Exceptions on domain lookup:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;

try {
    $whois = Factory::get()->createWhois();
    $info = $whois->loadDomainInfo("google.com");
    if (!$info) {
        print "Null if domain available";
        exit;
    }
    print $info->domainName . " expires at: " . date("d.m.Y H:i:s", $info->expirationDate);
} catch (ConnectionException $e) {
    print "Disconnect or connection timeout";
} catch (ServerMismatchException $e) {
    print "TLD server (.com for google.com) not found in current server hosts";
} catch (WhoisException $e) {
    print "Whois server responded with error '{$e->getMessage()}'";
}
```

##### Proxy with SOCKS5:
```php
<?php

use Iodev\Whois\Loaders\CurlLoader;
use Iodev\Whois\Factory;

$loader = new CurlLoader();
$loader->replaceOptions([
    CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5,
    CURLOPT_PROXY => "127.0.0.1:1080",
    //CURLOPT_PROXYUSERPWD => "user:pass",
]);
$whois = Factory::get()->createWhois($loader);

var_dump([
    'ya.ru' => $whois->loadDomainInfo('ya.ru'),
    'google.de' => $whois->loadDomainInfo('google.de'),
]);
```
The same curl options, including the proxy, are used for RDAP requests.

##### TLD hosts customization:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\TldServer;

$whois = Factory::get()->createWhois();

// Define custom whois host
$customServer = new TldServer(".custom", "whois.nic.custom", false, Factory::get()->createTldParser());

// Or define the same via assoc way
$customServer = TldServer::fromData([
    "zone" => ".custom",
    "host" => "whois.nic.custom",
]);

// Add custom server to existing whois instance
$whois->getTldModule()->addServers([$customServer]);

// Now it can be utilized
$info = $whois->loadDomainInfo("google.custom");

var_dump($info);
```

##### TLD default/fallback servers:
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Modules\Tld\TldServer;

$whois = Factory::get()->createWhois();

// Add default servers
$matchedServers = $whois->getTldModule()
    ->addServers(TldServer::fromDataList([
        ['zone' => '.*.net', 'host' => 'localhost'],
        ['zone' => '.uk.*', 'host' => 'localhost'],
        ['zone' => '.*', 'host' => 'localhost'],
    ]))
    ->matchServers('some.uk.net');

foreach ($matchedServers as $s) {
    echo "{$s->getZone()}  {$s->getHost()}\n";
}

// Matched servers + custom defaults:
//
// .uk.net  whois.centralnic.com
// .uk.net  whois.centralnic.net
// .uk.*  localhost
// .*.net  localhost
// .net  whois.crsnic.net
// .net  whois.verisign-grs.com
// .*  localhost
```

### ASN lookup

##### How to get summary using ASN number:
```php
<?php

use Iodev\Whois\Factory;

$whois = Factory::get()->createWhois();

// Getting raw-text lookup
$response = $whois->lookupAsn("AS32934");
print $response->text;

// Getting parsed ASN info
$info = $whois->loadAsnInfo("AS32934");
foreach ($info->routes as $route) {
    print_r([
        'route IPv4' => $route->route,
        'route IPv6' => $route->route6,
        'description' => $route->descr,
    ]);   
}

```

### Response caching
Some TLD hosts are very limited for frequent requests. Use cache if in your case requests are repeating.
RDAP responses are cached too.
```php
<?php

use Iodev\Whois\Factory;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Loaders\MemcachedLoader;

$m = new Memcached();
$m->addServer('127.0.0.1', 11211);
$loader = new MemcachedLoader(new SocketLoader(), $m);

$whois = Factory::get()->createWhois($loader);
// do something...
```


## Development
Supported php versions are configured in `docker-compose.yml`

Common use cases:
1. Set up & run all tests: `docker compose up --build`
2. Run tests under specific php version: `docker compose up php-8.5_intl --build`
3. Run scripts: `docker compose run php-8.5_intl bin/php-whois info google.com --mode rdapFirst`
4. Run the tests that query real servers: `composer test-live`

`tests/Iodev/Whois/Compat/ApiCompatibilityTest.php` fails if anything from the public or protected API
of io-developer/php-whois 4.1.10 is removed or changed. New classes and methods are fine.

The bundled server lists are maintained with `bin/update-servers` (`rdap`, `check`, `missing`).

Also see **TESTS.md**


## Contributing

The project is open for pull requests, issues and feedback. Please read the CODE_OF_CONDUCT.md

## Credits

Based on [io-developer/php-whois](https://github.com/io-developer/php-whois) by Sergey Sedyshev and
its contributors (MIT).
