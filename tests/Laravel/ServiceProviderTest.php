<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Tests\Laravel;

use Orchestra\Testbench\TestCase;
use SETechSolutions\Whois\DomainInfo;
use SETechSolutions\Whois\Laravel\Facades\Whois as WhoisFacade;
use SETechSolutions\Whois\Laravel\WhoisServiceProvider;
use SETechSolutions\Whois\Mode;
use SETechSolutions\Whois\Tests\Fakes\FakeHttpClient;
use SETechSolutions\Whois\Tests\Fakes\FakeWhoisClient;
use SETechSolutions\Whois\Whois;

class ServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [WhoisServiceProvider::class];
    }

    protected function getPackageAliases($app)
    {
        return ['Whois' => WhoisFacade::class];
    }

    private function useFakeServers()
    {
        $dir = __DIR__ . '/../fixtures/';
        $http = new FakeHttpClient([
            'https://rdap.verisign.com/com/v1/domain/google.com' => ['status' => 200, 'body' => file_get_contents($dir . 'rdap/google.com.json')],
        ]);
        $whoisClient = new FakeWhoisClient(file_get_contents($dir . 'whois/.com/google.com.txt'));
        $this->app->instance(Whois::class, new Whois(['follow_registrar' => false], $http, $whoisClient));
    }

    public function testDefaultConfigIsMerged()
    {
        $config = $this->app['config']->get('whois');

        $this->assertSame('rdap_first', $config['mode']);
        $this->assertSame(30, (int)$config['timeout']);
        $this->assertTrue($config['follow_registrar']);
        $this->assertSame([], $config['curl_options']);
        $this->assertSame([], $config['rdap_servers']);
        $this->assertSame([], $config['whois_servers']);
    }

    public function testContainerGivesOneSharedClient()
    {
        $whois = $this->app->make(Whois::class);

        $this->assertInstanceOf(Whois::class, $whois);
        $this->assertSame($whois, $this->app->make(Whois::class));
        $this->assertSame($whois, $this->app->make('whois'));
        $this->assertSame(Mode::RDAP_FIRST, $whois->options()['mode']);
    }

    public function testConfigReachesTheClient()
    {
        $this->app['config']->set('whois.mode', 'whois_only');
        $this->app['config']->set('whois.timeout', 7);
        $this->app['config']->set('whois.follow_registrar', false);
        $this->app['config']->set('whois.rdap_servers', ['example' => 'https://rdap.nic.example/']);

        $options = $this->app->make(Whois::class)->options();

        $this->assertSame(Mode::WHOIS_ONLY, $options['mode']);
        $this->assertSame(7, $options['timeout']);
        $this->assertFalse($options['follow_registrar']);
        $this->assertSame(['example' => 'https://rdap.nic.example/'], $options['rdap_servers']);
    }

    public function testFacade()
    {
        $this->useFakeServers();

        $info = WhoisFacade::lookup('google.com');

        $this->assertInstanceOf(DomainInfo::class, $info);
        $this->assertSame('google.com', $info->domain());
        $this->assertSame('rdap', $info->source());
        $this->assertFalse(WhoisFacade::isAvailable('google.com'));
        $this->assertTrue(WhoisFacade::isAvailable('free-domain.com'));
        $this->assertSame('whois', WhoisFacade::raw('google.com')->source());
    }

    public function testFacadeAlias()
    {
        $this->useFakeServers();

        $this->assertSame('google.com', \Whois::lookup('google.com')->domain());
    }

    public function testDomainInfoInAJsonResponse()
    {
        $this->useFakeServers();
        $this->app['router']->get('/whois/{domain}', function ($domain) {
            return response()->json(WhoisFacade::lookup($domain));
        });

        $response = $this->get('/whois/google.com');
        $response->assertStatus(200);
        $data = json_decode($response->getContent(), true);

        $this->assertSame('google.com', $data['domain']);
        $this->assertSame('MarkMonitor Inc.', $data['registrar']);
        $this->assertSame('2028-09-14T04:00:00+00:00', $data['expiresAt']);
    }

    public function testConfigCanBePublished()
    {
        $target = $this->app->configPath('whois.php');
        @unlink($target);

        $this->artisan('vendor:publish', ['--tag' => 'whois-config']);

        $this->assertFileExists($target);
        $this->assertSame(array_keys(require __DIR__ . '/../../config/whois.php'), array_keys(require $target));
        @unlink($target);
    }
}
