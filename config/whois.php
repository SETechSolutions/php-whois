<?php

return [

    /*
     | Which protocols a lookup uses, and in what order:
     |   rdap_first  RDAP, then WHOIS if RDAP fails (default)
     |   whois_first WHOIS, then RDAP if WHOIS fails
     |   rdap_only   RDAP only
     |   whois_only  WHOIS only
     | A zone that has a server for only one protocol uses that protocol in the two "first" modes.
     */
    'mode' => env('WHOIS_MODE', 'rdap_first'),

    /*
     | Seconds to wait for each request.
     */
    'timeout' => env('WHOIS_TIMEOUT', 30),

    /*
     | Registries such as .com link to the registrar's RDAP server, which usually knows the owner
     | and the registrar's WHOIS server. True makes a second request to fetch that.
     */
    'follow_registrar' => true,

    /*
     | Extra curl options for every request, for example a proxy:
     |   [CURLOPT_PROXY => '127.0.0.1:1080', CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5]
     | When set, WHOIS queries go through curl as well.
     */
    'curl_options' => [],

    /*
     | RDAP servers to add to the bundled list, zone => base URL:
     |   ['example' => 'https://rdap.nic.example/']
     */
    'rdap_servers' => [],

    /*
     | WHOIS servers to try before the bundled ones:
     |   [['zone' => '.example', 'host' => 'whois.nic.example']]
     */
    'whois_servers' => [],

];
