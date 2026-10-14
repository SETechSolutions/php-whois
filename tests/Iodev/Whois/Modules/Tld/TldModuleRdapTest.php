<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use InvalidArgumentException;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Loaders\FakeHttpLoader;
use Iodev\Whois\Loaders\FakeSocketLoader;
use Iodev\Whois\Loaders\SocketLoader;
use Iodev\Whois\Whois;
use PHPUnit\Framework\TestCase;

class TldModuleRdapTest extends TestCase
{
    const COM_URL = 'https://rdap.verisign.com/com/v1/domain/google.com';
    const REGISTRAR_URL = 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM';

    /** @var FakeHttpLoader */
    private $loader;

    /** @var Whois */
    private $whois;

    public function setUp(): void
    {
        $this->loader = new FakeHttpLoader();
        $this->loader->text = file_get_contents(__DIR__ . '/parsing_data/.com/google.com.txt');
        $this->loader->responses = [
            self::COM_URL => ['status' => 200, 'body' => self::rdapFile('google.com.json')],
            self::REGISTRAR_URL => ['status' => 200, 'body' => self::rdapFile('google.com_registrar.json')],
        ];
        $this->whois = new Whois($this->loader);
    }

    /**
     * @param string $filename
     * @return string
     */
    private static function rdapFile($filename)
    {
        return file_get_contents(__DIR__ . '/rdap_data/' . $filename);
    }

    public function testDefaultModeIsRdapFirst()
    {
        self::assertSame(LookupMode::RDAP_FIRST, $this->whois->getTldModule()->getLookupMode());
    }

    public function testLoadDomainInfoUsesRdapAndRegistrar()
    {
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertSame('rdap', $info->parserType);
        self::assertSame(TldResponse::SOURCE_RDAP, $info->getResponse()->getSource());
        self::assertSame(self::COM_URL, $info->getResponse()->query);
        self::assertSame('rdap.verisign.com', $info->getResponse()->host);
        // From the registrar
        self::assertSame('Google LLC', $info->owner);
        self::assertSame('whois.markmonitor.com', $info->whoisServer);
        // The registry's values win
        self::assertSame('MarkMonitor Inc.', $info->registrar);
        self::assertSame(strtotime('2028-09-14T04:00:00Z'), $info->expirationDate);
        self::assertInstanceOf(TldInfo::class, $info->getExtraVal('relatedInfo'));
        self::assertSame([self::COM_URL, self::REGISTRAR_URL], $this->loader->httpRequests);
        self::assertSame([], $this->loader->whoisRequests);
    }

    public function testFollowRelatedCanBeTurnedOff()
    {
        $this->whois->getTldModule()->setRdapFollowRelated(false);
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertSame('', $info->owner);
        self::assertSame([self::COM_URL], $this->loader->httpRequests);
    }

    public function testRegistrarFailureKeepsRegistryInfo()
    {
        $this->loader->responses[self::REGISTRAR_URL] = ['status' => 503, 'body' => ''];
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertSame('rdap', $info->parserType);
        self::assertSame('MarkMonitor Inc.', $info->registrar);
        self::assertSame('', $info->owner);
    }

    public function testRdapNotFoundMeansAvailable()
    {
        self::assertTrue($this->whois->isDomainAvailable('free-domain.com'));
        self::assertNull($this->whois->loadDomainInfo('free-domain.com'));
        self::assertSame([], $this->loader->whoisRequests);
    }

    public function testRdapServerErrorFallsBackToWhois()
    {
        $this->loader->responses[self::COM_URL] = ['status' => 503, 'body' => ''];
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertNotSame('rdap', $info->parserType);
        self::assertSame(TldResponse::SOURCE_WHOIS, $info->getResponse()->getSource());
        self::assertSame('google.com', $info->domainName);
        self::assertNotEmpty($this->loader->whoisRequests);
    }

    public function testRdapRateLimitFallsBackToWhois()
    {
        $this->loader->responses[self::COM_URL] = ['status' => 429, 'body' => ''];

        self::assertNotSame('rdap', $this->whois->loadDomainInfo('google.com')->parserType);
    }

    public function testRdapConnectionFailureFallsBackToWhois()
    {
        $this->loader->failOnHttp = true;

        self::assertNotSame('rdap', $this->whois->loadDomainInfo('google.com')->parserType);
    }

    public function testBothFailingThrowsFirstProtocolsError()
    {
        $this->loader->failOnHttp = true;
        $this->loader->failOnConnect = true;

        try {
            $this->whois->loadDomainInfo('google.com');
            self::fail('Expected ConnectionException');
        } catch (ConnectionException $e) {
            self::assertSame('Fake HTTP connection fault', $e->getMessage());
        }
        // lookupDomain() asks WHOIS first
        try {
            $this->whois->lookupDomain('google.com');
            self::fail('Expected ConnectionException');
        } catch (ConnectionException $e) {
            self::assertSame('Fake connection fault', $e->getMessage());
        }
    }

    public function testRdapOnlyPassesErrorsThrough()
    {
        $this->whois->setLookupMode(LookupMode::RDAP_ONLY);
        $this->loader->responses[self::COM_URL] = ['status' => 429, 'body' => ''];

        try {
            $this->whois->loadDomainInfo('google.com');
            self::fail('Expected WhoisException');
        } catch (WhoisException $e) {
            self::assertSame(429, $e->getCode());
        }
        self::assertSame([], $this->loader->whoisRequests);
    }

    public function testWhoisOnlyNeverUsesRdap()
    {
        $this->whois->setLookupMode(LookupMode::WHOIS_ONLY);
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertNotSame('rdap', $info->parserType);
        self::assertSame([], $this->loader->httpRequests);
    }

    public function testWhoisFirstFallsBackToRdap()
    {
        $this->whois->setLookupMode(LookupMode::WHOIS_FIRST);
        self::assertNotSame('rdap', $this->whois->loadDomainInfo('google.com')->parserType);
        self::assertSame([], $this->loader->httpRequests);

        $this->loader->failOnConnect = true;
        self::assertSame('rdap', $this->whois->loadDomainInfo('google.com')->parserType);
    }

    public function testLookupDomainPrefersWhoisText()
    {
        $response = $this->whois->lookupDomain('google.com');

        self::assertSame(TldResponse::SOURCE_WHOIS, $response->getSource());
        self::assertSame($this->loader->text, $response->text);
        self::assertSame([], $this->loader->httpRequests);
    }

    public function testLookupDomainFallsBackToRdapJson()
    {
        $this->loader->failOnConnect = true;
        $response = $this->whois->lookupDomain('google.com');

        self::assertSame(TldResponse::SOURCE_RDAP, $response->getSource());
        self::assertSame(200, $response->getHttpStatus());
        self::assertSame('GOOGLE.COM', json_decode($response->text, true)['ldhName']);
    }

    public function testZoneWithoutRdapUsesWhois()
    {
        $this->whois->getTldModule()->getRdapBootstrap()->setServers([]);
        $info = $this->whois->loadDomainInfo('google.com');

        self::assertNotSame('rdap', $info->parserType);
        self::assertSame([], $this->loader->httpRequests);
    }

    public function testZoneWithOnlyRdapWorks()
    {
        $this->whois->getTldModule()->setServers([]);
        $this->whois->getTldModule()->getRdapBootstrap()->setServers(['test' => 'https://rdap.test/']);
        $this->loader->responses['https://rdap.test/domain/google.test'] = [
            'status' => 200,
            'body' => str_replace('GOOGLE.COM', 'GOOGLE.TEST', self::rdapFile('google.com.json')),
        ];

        self::assertSame('google.test', $this->whois->loadDomainInfo('google.test')->domainName);
    }

    public function testNoServersAtAll()
    {
        $this->expectException(ServerMismatchException::class);
        $this->whois->loadDomainInfo('google.zz-unknown');
    }

    public function testExplicitServerUsesWhois()
    {
        $mod = $this->whois->getTldModule();
        $server = $mod->matchServers('google.com')[0];

        self::assertNotSame('rdap', $mod->loadDomainInfo('google.com', $server)->parserType);
        self::assertSame(TldResponse::SOURCE_WHOIS, $mod->lookupDomain('google.com', $server)->getSource());
        self::assertSame([], $this->loader->httpRequests);
    }

    public function testUnknownModeIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->whois->setLookupMode('fast');
    }

    public function testWhoisOnlyLoaderNeverUsesRdap()
    {
        $loader = new FakeSocketLoader();
        $loader->text = $this->loader->text;
        $whois = new Whois($loader);

        self::assertNull($whois->getTldModule()->getHttpLoader());
        self::assertNotSame('rdap', $whois->loadDomainInfo('google.com')->parserType);
    }

    public function testBuiltInLoaderSupportsRdap()
    {
        $whois = new Whois(new SocketLoader());

        self::assertNotNull($whois->getTldModule()->getHttpLoader());
    }

    public function testSetHttpLoader()
    {
        $loader = new FakeSocketLoader();
        $loader->failOnConnect = true;
        $whois = new Whois($loader);
        $whois->getTldModule()->setHttpLoader($this->loader);

        self::assertSame('rdap', $whois->loadDomainInfo('google.com')->parserType);
    }
}
