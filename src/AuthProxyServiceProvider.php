<?php
namespace Saad\Passport;

use Carbon\Carbon;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;
use Optimus\ApiConsumer\Provider\LaravelServiceProvider;
use Saad\Passport\AuthProxy;
use Saad\Passport\Contracts\AuthProxyContract;

class AuthProxyServiceProvider extends ServiceProvider
{
	/**
	 * Booting
	 */
	public function boot()
	{
		// Register Passport routes
		Passport::routes(function ($route) {
            $route->forAccessTokens();
            $route->forTransientTokens();
        });

        Passport::tokensExpireIn(Carbon::parse('+2 weeks'));
        Passport::refreshTokensExpireIn(Carbon::parse('+4 weeks'));
	}

	/**
	 * Register AuthProxy
	 */
	public function register()
	{
		$this->app->register(LaravelServiceProvider::class);
		$this->app->bind(AuthProxyContract::class, AuthProxy::class);
	}
}