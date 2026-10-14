<?php

declare(strict_types=1);

namespace SETechSolutions\Whois\Laravel;

use Illuminate\Support\ServiceProvider;
use SETechSolutions\Whois\Whois;

class WhoisServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/whois.php', 'whois');

        $this->app->singleton(Whois::class, function ($app) {
            return new Whois((array)$app['config']->get('whois', []));
        });
        $this->app->alias(Whois::class, 'whois');
    }

    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/whois.php' => $this->app->configPath('whois.php'),
            ], 'whois-config');
        }
    }
}
