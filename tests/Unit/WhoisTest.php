<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SETechSolutions\Whois\DomainInfo;
use SETechSolutions\Whois\Exceptions\ConnectionException;
use SETechSolutions\Whois\Exceptions\InvalidDomainException;
use SETechSolutions\Whois\Exceptions\RateLimitException;
use SETechSolutions\Whois\Exceptions\UnsupportedTldException;
use SETechSolutions\Whois\Exceptions\WhoisException;
use SETechSolutions\Whois\Mode;
use SETechSolutions\Whois\Tests\Fakes\FakeHttpClient;
use SETechSolutions\Whois\Tests\Fakes\FakeWhoisClient;
use SETechSolutions\Whois\Whois;

class WhoisTest extends TestCase
{
    const COM_URL = 'https://rdap.verisign.com/com/v1/domain/google.com';
    const REGISTRAR_URL = 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM';

    /** @var FakeHttpClient */
    private $http;

    /** @var FakeWhoisClient */
    private $whoisClient;

    protected function setUp(): void
    {
        $this->http = new FakeHttpClient([
            self::COM_URL => ['status' => 200, 'body' => self::fixture('rdap/google.com.json')],
            self::REGISTRAR_URL => ['status' => 200, 'body' => self::fixture('rdap/google.com_registrar.json')],
        ]);
        $this->whoisClient = new FakeWhoisClient(self::fixture('whois/.com/google.com.txt'));
    }

    private static function fixture(string $path): string
    {
        return file_get_contents(__DIR__ . '/../fixtures/' . $path);
    }

    private function whois(array $options = []): Whois
    {
        return new Whois($options, $this->http, $this->whoisClient);
    }

    public function testDefaults()
    {
        $options = (new Whois())->options();

        $this->assertSame(Mode::RDAP_FIRST, $options['mode']);
        $this->assertSame(30, $options['timeout']);
        $this->assertTrue($options['follow_registrar']);
        $this->assertSame([], $options['curl_options']);
    }

    public function testOptionsAreNormalized()
    {
        $options = (new Whois(['mode' => null, 'timeout' => '12', 'follow_registrar' => 0, 'unknown' => 'ignored']))->options();

        $this->assertSame(Mode::RDAP_FIRST, $options['mode']);
        $this->assertSame(12, $options['timeout']);
        $this->assertFalse($options['follow_registrar']);
    }

    public function testUnknownModeIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        new Whois(['mode' => 'fast']);
    }

    public function testLookupUsesRdapAndTheRegistrar()
    {
        $info = $this->whois()->lookup('google.com');

        $this->assertInstanceOf(DomainInfo::class, $info);
        $this->assertSame('google.com', $info->domain());
        $this->assertSame('rdap', $info->source());
        $this->assertSame('rdap.verisign.com', $info->raw()->server());
        $this->assertSame(self::COM_URL, $info->raw()->query());
        // From the registrar
        $this->assertSame('Google LLC', $info->owner());
        $this->assertSame('whois.markmonitor.com', $info->whoisServer());
        // The registry's values win
        $this->assertSame('MarkMonitor Inc.', $info->registrar());
        $this->assertSame('2028-09-14T04:00:00+00:00', $info->expiresAt()->format(DATE_ATOM));
        $this->assertSame([self::COM_URL, self::REGISTRAR_URL], $this->http->requests);
        $this->assertSame([], $this->whoisClient->requests);
    }

    public function testRegistrarFollowUpCanBeTurnedOff()
    {
        $info = $this->whois(['follow_registrar' => false])->lookup('google.com');

        $this->assertSame('', $info->owner());
        $this->assertSame([self::COM_URL], $this->http->requests);
    }

    public function testRegistrarFailureKeepsTheRegistryAnswer()
    {
        $this->http->responses[self::REGISTRAR_URL] = ['status' => 503, 'body' => ''];
        $info = $this->whois()->lookup('google.com');

        $this->assertSame('rdap', $info->source());
        $this->assertSame('MarkMonitor Inc.', $info->registrar());
        $this->assertSame('', $info->owner());
    }

    public function testNotFoundMeansAvailable()
    {
        $whois = $this->whois();

        $this->assertNull($whois->lookup('free-domain.com'));
        $this->assertTrue($whois->isAvailable('free-domain.com'));
        $this->assertFalse($whois->isAvailable('google.com'));
        $this->assertSame([], $this->whoisClient->requests);
    }

    public function testRdapServerErrorFallsBackToWhois()
    {
        $this->http->responses[self::COM_URL] = ['status' => 503, 'body' => ''];
        $info = $this->whois()->lookup('google.com');

        $this->assertSame('whois', $info->source());
        $this->assertSame('google.com', $info->domain());
        $this->assertNotEmpty($this->whoisClient->requests);
    }

    public function testRdapRateLimitFallsBackToWhois()
    {
        $this->http->responses[self::COM_URL] = ['status' => 429, 'body' => ''];

        $this->assertSame('whois', $this->whois()->lookup('google.com')->source());
    }

    public function testRdapConnectionFailureFallsBackToWhois()
    {
        $this->http->fail = true;

        $this->assertSame('whois', $this->whois()->lookup('google.com')->source());
    }

    public function testUnexpectedRdapBodyFallsBackToWhois()
    {
        $this->http->responses[self::COM_URL] = ['status' => 200, 'body' => '<html>maintenance</html>'];

        $this->assertSame('whois', $this->whois()->lookup('google.com')->source());
    }

    public function testWhenBothFailTheFirstProtocolsErrorIsThrown()
    {
        $this->http->fail = true;
        $this->whoisClient->fail = true;

        try {
            $this->whois()->lookup('google.com');
            $this->fail('Expected ConnectionException');
        } catch (ConnectionException $e) {
            $this->assertSame('Fake HTTP connection fault', $e->getMessage());
        }
        // raw() asks WHOIS first
        try {
            $this->whois()->raw('google.com');
            $this->fail('Expected ConnectionException');
        } catch (ConnectionException $e) {
            $this->assertSame('Fake WHOIS connection fault', $e->getMessage());
        }
    }

    public function testRdapOnlyPassesErrorsThrough()
    {
        $this->http->responses[self::COM_URL] = ['status' => 429, 'body' => ''];

        try {
            $this->whois(['mode' => Mode::RDAP_ONLY])->lookup('google.com');
            $this->fail('Expected RateLimitException');
        } catch (RateLimitException $e) {
            $this->assertSame(429, $e->getCode());
            $this->assertInstanceOf(WhoisException::class, $e);
        }
        $this->assertSame([], $this->whoisClient->requests);
    }

    public function testWhoisOnlyNeverUsesRdap()
    {
        $info = $this->whois(['mode' => Mode::WHOIS_ONLY])->lookup('google.com');

        $this->assertSame('whois', $info->source());
        $this->assertSame('MarkMonitor Inc.', $info->registrar());
        $this->assertSame([], $this->http->requests);
    }

    public function testWhoisFirstFallsBackToRdap()
    {
        $this->assertSame('whois', $this->whois(['mode' => Mode::WHOIS_FIRST])->lookup('google.com')->source());
        $this->assertSame([], $this->http->requests);

        $this->whoisClient->fail = true;
        $this->assertSame('rdap', $this->whois(['mode' => Mode::WHOIS_FIRST])->lookup('google.com')->source());
    }

    public function testRawPrefersWhoisText()
    {
        $raw = $this->whois()->raw('google.com');

        $this->assertSame('whois', $raw->source());
        $this->assertSame($this->whoisClient->text, $raw->text());
        $this->assertSame([], $this->http->requests);
    }

    public function testRawFallsBackToRdapJson()
    {
        $this->whoisClient->fail = true;
        $raw = $this->whois()->raw('google.com');

        $this->assertSame('rdap', $raw->source());
        $this->assertSame('GOOGLE.COM', json_decode($raw->text(), true)['ldhName']);
    }

    public function testRawInRdapOnlyMode()
    {
        $this->assertSame('rdap', $this->whois(['mode' => Mode::RDAP_ONLY])->raw('google.com')->source());
        $this->assertSame([], $this->whoisClient->requests);
    }

    public function testZoneWithoutRdapUsesWhois()
    {
        // .de has no RDAP server
        $this->whoisClient->text = self::fixture('whois/.de/google.de.txt');
        $info = $this->whois()->lookup('google.de');

        $this->assertSame('whois', $info->source());
        $this->assertSame('google.de', $info->domain());
        $this->assertSame([], $this->http->requests);
    }

    public function testExtraRdapServer()
    {
        $this->http->responses['https://rdap.nic.example/domain/shop.example'] = [
            'status' => 200,
            'body' => str_replace('GOOGLE.COM', 'SHOP.EXAMPLE', self::fixture('rdap/google.com.json')),
        ];
        $whois = $this->whois(['rdap_servers' => ['example' => 'https://rdap.nic.example'], 'follow_registrar' => false]);

        $this->assertSame('shop.example', $whois->lookup('shop.example')->domain());
    }

    public function testExtraWhoisServerIsAskedFirst()
    {
        $whois = $this->whois(['mode' => Mode::WHOIS_ONLY, 'whois_servers' => [['zone' => '.com', 'host' => 'whois.mine.example']]]);
        $whois->lookup('google.com');

        $this->assertSame('whois.mine.example', $this->whoisClient->requests[0]);
    }

    public function testUnknownZone()
    {
        $this->expectException(UnsupportedTldException::class);
        $this->whois()->lookup('google.zz-unknown');
    }

    public function testZoneUnsupportedInTheChosenMode()
    {
        // .de exists, but only over WHOIS
        $this->expectException(UnsupportedTldException::class);
        $this->whois(['mode' => Mode::RDAP_ONLY])->lookup('google.de');
    }

    public function testInternationalDomainIsConvertedToPunycode()
    {
        $this->whoisClient->text = self::fixture('whois/.de/google.de.txt');
        $this->whois()->lookup(' MÜNCHEN.de ');

        $this->assertNotEmpty($this->whoisClient->requests);
        // Not found over RDAP is asked with the ASCII name
        $this->whois()->lookup('пример.com');
        $this->assertSame('https://rdap.verisign.com/com/v1/domain/xn--e1afmkfd.com', end($this->http->requests));
    }

    public function testInvalidDomains()
    {
        foreach (['', '   ', 'exa mple.com', 'https://example.com/path', 'example..com', '-example.com', 'user@example.com'] as $input) {
            try {
                $this->whois()->lookup($input);
                $this->fail("'$input' was accepted as a domain");
            } catch (InvalidDomainException $e) {
                $this->assertInstanceOf(WhoisException::class, $e);
            }
        }
        $this->assertSame([], $this->http->requests);
        $this->assertSame([], $this->whoisClient->requests);
    }
}
