<?php

/**
 * This Class is aproxy for Laravel Passport AccessTokens and TransientTokens
 * for authentication users by their credentials
 * used for login and logout and refresh expired tokens
 *
 * @package  passport-auth-proxy
 * @author  <a7mad.sa3d.2014@gmail.com>
 * @version  1.1.0 Release
 */

namespace Saad\Passport;

use Illuminate\Auth\AuthManager;
use Illuminate\Cookie\CookieJar;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use League\OAuth2\Server\ResourceServer;
use Optimus\ApiConsumer\Router;
use Saad\Passport\Contracts\AuthProxyContract;
use Saad\Passport\Exceptions\InvalidCredentialsException;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;

class AuthProxy implements AuthProxyContract
{
	/**
	 * Api Consumer
	 * @var Optimus\ApiConsumer\Router
	 */
	protected $apiConsumer;

	/**
	 * Cookie
	 * @var 
	 */
	protected $cookie;

	/**
	 * Request
	 * @var 
	 */
	protected $request;

	/**
	 * oAuth Server Client ID
	 * @var Integer|String
	 */
	protected $client_id;

	/**
	 * oAuth ClientSecret
	 * @var String
	 */
	protected $client_secret;

	/**
	 * oAuth ressource server
	 * @var League\OAuth2\Server\ResourceServer
	 */
	protected $resource_server;

	/**
	 * Http Only Refresh Token
	 * @var boolean
	 */
	protected $http_only_refresh_token = true;

	public function __construct(Application $app, CookieJar $cookie, Request $request, AuthManager $auth, DatabaseManager $db)
	{
		$this->apiConsumer = $app->make('apiconsumer');
		$this->cookie = $cookie;
		$this->request = $request;
		$this->auth = $auth;
		$this->db = $db;

		$this->setClientId();
		$this->setClientSecret();
	}

	/**
	 * Try To Login User and get tokens
	 * @param  array  $credentials User Credentials
	 * @return array              Tokens
	 * @throws \Saad\Passport\Exceptions\InvalidCredentialsException If credentials are wrong
	 */
	public function attemptLogin($username, $password, array $scopes = [])
	{
		return $this->proxy('password', [
			'username' => $username,
			'password' => $password,
			'scope' => implode(' ', $scopes),
		]);
	}

	/**
	 * Refresh Token
	 *
	 * used to get new tokens by a refresh token for expired tokens
	 * if called in httponly refresh token cookie mode it will only look for refresh token in request cookie
	 * and ignore given argument
	 *
	 * to use refresh by given refresh token you have to call includeRefreshToken() first
	 * 
	 * @param  String  $refresh_token RefreshToken
	 * @return array              Tokens
	 * @throws \Saad\Passport\Exceptions\InvalidCredentialsException If credentials are wrong
	 */
	public function attemptRefresh($refresh_token = null)
	{
		// If HttpOnly Cookie mode, we will look for request refresh token cookie
		if ($this->http_only_refresh_token) {
			$refresh_token = $this->request->cookie('refresh_token');
			if (is_null($refresh_token)) {
				throw new InvalidCredentialsException('Missing refresh token cookie');
			}
		} else if(is_null($refresh_token)){
			throw new InvalidCredentialsException('Missing refresh token');
		}

		return $this->proxy('refresh_token', [
			'refresh_token' => $refresh_token,
		]);
	}

	/**
	 * Logout
	 *
	 * used to Logout authenticated user by revoking user token and refresh token
	 *
	 * @return  void
	 */
	public function logout($access_token = null)
	{
		if ($this->auth->check()) {
			// Get Access Token
			$token = $this->auth->user()->token();

			if ($token) {
				// Revoke Refresh Token from db
				$this->db->table('oauth_refresh_tokens')
						->where('access_token_id', $token->id)
						->update(['revoked' => true]);

				// Revoke Access Token
				$token->revoke();
			}

			// Kill Refresh Token Cookie
			$this->cookie->queue($this->cookie->forget('refresh_token'));
		}
	}

	/**
	 * Set oAuth Client Id
	 * @param Integer $id Client ID
	 */
	public function setClientId($id = null)
	{
		$this->client_id = is_null($id) ? env('PASSWORD_CLIENT_ID') : $id;
		return $this;
	}

	/**
	 * Get oAuth Client Id
	 * @return Integer $id Client ID
	 */
	public function getClientId()
	{
		return $this->client_id;
	}

	/**
	 * Get oAuth Client Secret
	 * @return String Client Secret
	 */
	public function getClientSecret()
	{
		return $this->client_secret;
	}

	/**
	 * Set oAuth Client Secret
	 * @param String $secret Client Secret
	 */
	public function setClientSecret($secret = null)
	{
		$this->client_secret = is_null($secret) ? env('PASSWORD_CLIENT_SECRET') : $secret;
		return $this;
	}

	/**
	 * Include Refresh Token in response
	 * @return AuthProxy
	 */
	public function includeRefreshToken()
	{
		$this->http_only_refresh_token = false;
		return $this;
	}

	/**
	 * Call oAuth Server And Get Response
	 * @param  String $grant_type Grant Type like 'password' or 'refresh_token'
	 * @param  array  $data       Data To Send To oAuth
	 * @return array             oAuth Response
	 * @throws InvalidCredentialsException On Invalid Credentials OR Invalid Client
	 */
	protected function proxy($grant_type, array $data)
	{
		$response = $this->apiConsumer->post('/oauth/token', array_merge([
			'grant_type' => $grant_type,
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
		], $data));

		if (!$response->isSuccessful()) {
			// Error Authentication
			try {
				$message = json_decode($response->getContent())->message;
			} catch (\Exception $e) {
				$message = '';
			}
			
			throw new InvalidCredentialsException($message);
		}

		$response = json_decode($response->getContent(), true);

		$this->processRefreshToken($response);

		return $response;
	}

	/**
	 * Process Refresh Token
	 *
	 * Check if to return refreshtoken with access token
	 * Or Store as HttpOnly Cookie
	 * 
	 * @param  array  &$response [description]
	 * @return [type]            [description]
	 */
	protected function processRefreshToken(array &$response)
	{
		// dd($response);
		if (!$this->http_only_refresh_token) {
			return;
		}

		$refresh_token = $response['refresh_token'];
		unset($response['refresh_token']);

		// Set Cookie
		$this->cookie->queue(
			'refresh_token',
			$refresh_token,
			864000,
			null,
			null,
			false,
			true
		);
	}

	/**
	 * Get User Id from access token
	 * @param  string $access_token Access Token
	 * @return integer|null               user id OR null if could not be found
	 */
	public function getUserIdFromAccessToken($access_token)
	{
		$request = Request::createFrom(app()->make('request'));
		$request->headers->add(['Authorization' => 'Bearer ' . $access_token]);
		try {
			$server = app()->make(ResourceServer::class);
		    $psr = (new DiactorosFactory)->createRequest($request);
		    $psr = $server->validateAuthenticatedRequest($psr);
		    return $psr->getAttribute('oauth_user_id');
		} catch (\Exception $e) {
			return null;
		}
	}
}