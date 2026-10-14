# Changelog

Versions continue the numbering of io-developer/php-whois, which this package replaces.

## 4.2.0 (2026-10-14)

First release as `setechsolutions/php-whois`. A drop-in replacement for io-developer/php-whois 4.1.10:
every public and protected class, method and constant of 4.1.10 is still there with the same signature
(checked by `tests/Iodev/Whois/Compat/ApiCompatibilityTest.php`).

### Added
- RDAP lookups. `loadDomainInfo()` and `isDomainAvailable()` ask RDAP first and fall back to WHOIS.
  `lookupDomain()` still returns WHOIS text and falls back to RDAP JSON.
- `LookupMode` (`RDAP_FIRST`, `WHOIS_FIRST`, `RDAP_ONLY`, `WHOIS_ONLY`), set with
  `Whois::setLookupMode()` or `TldModule::setLookupMode()`.
- `TldResponse::getSource()` (`rdap` or `whois`) and `TldResponse::getHttpStatus()`.
- `RdapParser` (`TldParser::RDAP`): fills the usual `TldInfo` fields from RDAP JSON, in the formats the
  WHOIS parsers use. The decoded JSON is in `$info->getExtraVal('rdap')`.
- `RdapBootstrap`: RDAP servers per zone from a bundled snapshot of IANA's bootstrap file
  (2026-09-30), with `addServers()` for your own and `loadFromIana()` for the current list.
- The registrar's RDAP record is fetched when the registry links to it (.com, .net and others);
  `TldModule::setRdapFollowRelated(false)` turns that off.
- `IHttpLoader`, implemented by `SocketLoader`, `CurlLoader` (same proxy options as WHOIS) and
  `MemcachedLoader` (caches RDAP responses). `TldModule::setHttpLoader()` sets a separate one.
- `bin/php-whois`: `--mode` option. `bin/update-servers`: maintains the bundled server lists.
- Tests run on PHP 7.2 to 8.5 in GitHub Actions; `composer test-live` queries real servers.

### Changed
- When RDAP and WHOIS both fail, the error of the protocol that was tried first is thrown.
- WHOIS server list (`module.tld.servers.json`), 1370 entries before, 1316 now:
  - 110 entries removed: the hostname no longer resolves, or the server answers that WHOIS was
    retired, and the zone has RDAP. In `WHOIS_ONLY` mode these zones now throw
    `ServerMismatchException` instead of failing to connect or reporting every domain as available.
  - 29 hosts replaced by the one IANA lists now (for example `.co`, `.tr`, `.in`, `.sc`, `.vc`).
  - 56 TLDs added.

### Fixed (all present in io-developer/php-whois 4.1.10)
- PHP 8.4+: "Implicitly marking parameter as nullable is deprecated" in 17 places.
- PHP 8.2+: "Creation of dynamic property" for custom parser classes based on `CommonParser`.
- PHP 8.5: `curl_close()` deprecation in `CurlLoader`.
- PHP 8.x: non-UTF-8 WHOIS replies (Latin-1, Windows-1251) lost their non-ASCII characters.
- PHP 7.x: `json_encode()` of `TldInfo`, `TldResponse` and the ASN objects threw a `TypeError`.

### Not changed
- ASN lookups use WHOIS only.
- A loader that does not implement `IHttpLoader`, or a subclass of `SocketLoader` / `CurlLoader` that
  overrides `loadText()` without `loadHttp()`, is used for WHOIS only, as before.
