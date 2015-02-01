<?php namespace Google\Authenticator;

/**
 * Class GoogleAuthenticator
 *
 * @package Google\Authenticator
 */
interface OneTimePasswordInterface
{
	/**
	 * @param $secret
	 * @param $code
	 *
	 * @return bool
	 */
	public function checkCode($secret, $code);

	/**
	 * @param       $secret
	 * @param  null $time
	 *
	 * @return string
	 */
	public function getCode($secret, $time = null);

	/**
	 * @param  string $user
	 * @param  string $hostname
	 * @param  string $secret
	 *
	 * @return string
	 */
	public function getUrl($user, $hostname, $secret);

	/**
	 * @return string
	 */
	public function generateSecret();
}