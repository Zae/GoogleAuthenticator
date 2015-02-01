<?php namespace Google\Authenticator; 

use Illuminate\Support\ServiceProvider;

class GoogleAuthenticatorServiceProvider extends ServiceProvider
{
	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		$this->registerIoCBindings();
	}

	private function registerIoCBindings()
	{
		$this->app->bind('Google\Authenticator\FixedBitNotation', function () {
			return new FixedBitNotation(5, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', true, true);
		});

		$this->app->bind('Google\Authenticator\OneTimePasswordInterface', 'Google\Authenticator\GoogleAuthenticator');
	}
}