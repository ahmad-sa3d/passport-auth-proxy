<?php

/**
 * @package  saad/passport-auth-proxy
 *
 * @author Ahmed Saad <a7mad.sa3d.2014@gmail.com>
 * @license MIT MIT
 */

namespace Saad\Passport\Contracts;

interface AuthProxyContract
{
	/**
	 * Login user by credentials and get Tokens
	 * 
	 * @param  array  $credentials User Credentials
	 * @return array              Tokens
	 * @throws \App\Services\Auth\Exceptions\InvalidCredentialsException If credentials are wrong
	 */
	public function attemptLogin($username, $password);

	/**
	 * Refresh Token
	 *
	 * used to get new tokens by a refresh token for expired tokens
	 * 
	 * @param  String  $refresh_token RefreshToken
	 * @return array              Tokens
	 * @throws \App\Services\Auth\Exceptions\InvalidCredentialsException If credentials are wrong
	 */
	public function attemptRefresh($refresh_token);

	/**
	 * Logout
	 *
	 * used to Logout authenticated user by revoking user token and refresh token
	 *
	 * @return  void
	 */
	public function logout();

	/**
	 * Set oAuth Client Id
	 * @param Integer $id Client ID
	 * @return AuthProxy
	 */
	public function setClientId($id);

	/**
	 * Get oAuth Client Id
	 * @return Integer Client ID
	 */
	public function getClientId();

	/**
	 * Set oAuth Client Secret
	 * @param String $secret Client Secret
	 * @return AuthProxy
	 */
	public function setClientSecret($secret);

	/**
	 * Get oAuth Client Secret
	 * @return String Client Secret
	 */
	public function getClientSecret();

	/**
	 * Include Refresh Token in response
	 * @return AuthProxy
	 */
	public function includeRefreshToken();
}