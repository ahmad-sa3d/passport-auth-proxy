<?php

/**
 * Test Cases for Passport Auth Proxy
 *
 * @author  Ahmed Saad <a7mad.sa3d.2014@gmail.com>
 * @package passport auth proxy
 * @license MIT
 * @version 1.0.0 First Version
 */

use Illuminate\Auth\AuthManager;
use Illuminate\Cookie\CookieJar;
use Illuminate\Database\DatabaseManager;
use Laravel\Passport\Token;
use Orchestra\Testbench\TestCase;
use Saad\Passport\AuthProxy;

/**
 * @coversDefaultClass Saad\Passport\AuthProxy
 */
class TestAuthProxy extends TestCase
{
	public function setUp()
	{
		parent::setUp();
	}

	public function getPackageProviders($app)
	{
		return [
			'\Saad\Passport\AuthProxyServiceProvider',
			'\Optimus\ApiConsumer\Provider\LaravelServiceProvider',
		];
	}

    /**
     * @test
     */
    public function it_throw_exeption_on_login_invalid_credentials_or_invalid_client()
    {
    	$this->mockConsumer(false, ['message' => 'error']);

    	$proxy = app()->make(AuthProxy::class);
    	$this->expectException('\Saad\Passport\Exceptions\InvalidCredentialsException');
    	$proxy->attemptLogin('any@test.com', '123456789');
    }

    /**
     * @test
     */
    public function it_return_tokens_on_successful_credentials_without_refresh_token()
    {
    	$this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);

    	$proxy = app()->make(AuthProxy::class);
    	$response = $proxy->attemptLogin('any@test.com', '123456789');
    	$this->assertArrayHasKey('access_token', $response);
    	$this->assertArrayNotHasKey('refresh_token', $response);
    }

    /**
     * @test
     */
    public function it_return_tokens_with_refresh_token_key_and_doesnot_store_as_cookie()
    {
    	$cookie = $this->getCookieMock();
    	$cookie->expects($this->never())
	    	->method('queue');

    	$this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);

    	$proxy = app()->make(AuthProxy::class);
    	$proxy->includeRefreshToken();
    	$response = $proxy->attemptLogin('any@test.com', '123456789');
    	$this->assertArrayHasKey('access_token', $response);
    	$this->assertArrayHasKey('refresh_token', $response);
    }

    /**
     * @test
     */
    public function it_stores_refresh_token_as_http_only_cookie()
    {
    	$cookie = $this->getCookieMock();
    	$cookie->expects($this->once())
	    	->method('queue')
    		->with('refresh_token');

    	$this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);

    	$proxy = app()->make(AuthProxy::class);
    	$response = $proxy->attemptLogin('any@test.com', '123456789');
    }

    /**
     * @test
     */
    public function it_can_set_and_get_client_id()
    {
    	$id = 3;
    	$proxy = app()->make(AuthProxy::class);
    	$proxy->setClientId($id);
    	$this->assertEquals($id, $proxy->getClientId());
    }

    /**
     * @test
     */
    public function it_can_set_and_get_client_secret()
    {
    	// Moke Api Consumer
    	$secret = '12345';
    	$proxy = app()->make(AuthProxy::class);
    	$proxy->setClientSecret($secret);
    	$this->assertEquals($secret, $proxy->getClientSecret());
    }

    /**
     * @test
     */
    public function it_cannot_refresh_invalid_refresh_tokens()
    {
        $this->mockConsumer(false, ['message' => 'Invalid Credentials']);
        $proxy = app()->make(AuthProxy::class);
        $this->expectException('\Saad\Passport\Exceptions\InvalidCredentialsException');
        $proxy->attemptRefresh('trtrrt');
    }

    /**
     * @test
     */
    public function it_can_refresh_tokens_by_valid_refresh_token()
    {
        $this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);

        $proxy = app()->make(AuthProxy::class);
        $proxy->includeRefreshToken();
        $response = $proxy->attemptLogin('any@test.com', '123456789');
        
        $new_response = $proxy->attemptRefresh($response['refresh_token']);
        $this->assertArrayHasKey('access_token', $new_response);
    }

    /**
     * @test
     */
    // public function it_can_refresh_tokens_from_http_only_cookie()
    // {
    //     $request = $this->getRequestMock();
    //     $request->expects($this->once())
    //         ->method('cookie')
    //         ->with('refresh_token')
    //         ->willReturn('12345');
            
    //     $this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);

    //     $proxy = app()->make(AuthProxy::class);
    //     $proxy->attemptRefresh();
    // }

    // /**
    //  * @test
    //  */
    // public function it_throws_exception_when_refresh_tokens_from_non_existing_http_only_cookie_in_http_only_cookie_mode()
    // {
    //     $request = $this->getRequestMock();
    //     $request->expects($this->once())
    //         ->method('cookie')
    //         ->with('refresh_token')
    //         ->willReturn(null);

    //     $this->expectException('\Saad\Passport\Exceptions\InvalidCredentialsException');

    //     $this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);
    //     $proxy = app()->make(AuthProxy::class);
    //     $proxy->attemptRefresh();
    // }

    /**
     * @test
     */
    public function it_throws_exception_when_refresh_tokens_without_give_refresh_token_in_include_refresh_token_mode()
    {
        $this->expectException('\Saad\Passport\Exceptions\InvalidCredentialsException');

        $this->mockConsumer(true, ['access_token' => 'any', 'refresh_token' => '12345']);
        $proxy = app()->make(AuthProxy::class);
        $proxy->includeRefreshToken();
        $proxy->attemptRefresh();
    }

    /** @test */
    public function it_can_logout_or_revoke_user_token()
    {
        $tokenMock = $this->getTokenMock();
        $authMock = $this->getAuthMock();
        $userMock = $this->getUserMock();
        $dbMock = $this->getDBMock();
        $cookieMoke = $this->getCookieMock();

        $authMock->expects($this->once())
            ->method('check')
            ->willReturn(true);

        $authMock->expects($this->once())
            ->method('user')
            ->willReturn($userMock);

        $userMock->expects($this->once())
            ->method('token')
            ->willReturn($tokenMock);

        // Mock DB Scenario for revoke refresh token
        $dbMock->expects($this->once())
            ->method('table')
            ->with('oauth_refresh_tokens')
            ->will($this->returnSelf());

        $dbMock->expects($this->once())
            ->method('where')
            ->with('access_token_id', $this->anything())
            ->will($this->returnSelf());

        $dbMock->expects($this->once())
            ->method('update')
            ->with(['revoked' => true])
            ->willReturn(true);

        $tokenMock->expects($this->once())
            ->method('revoke');

        $cookieMoke->expects($this->once())
            ->method('forget')
            ->with('refresh_token');

        $cookieMoke->expects($this->once())
            ->method('queue');

        $proxy = app()->make(AuthProxy::class);
        $proxy->logout();
    }

    /**
     * Mock Token
     * @return Token Mocked Token
     */
    protected function getTokenMock()
    {
        $tokenMock = $this->getMockBuilder(Token::class)
            ->setMethods(['revoke'])
            ->getMock();

        return $tokenMock;
    }

    /**
     * Mock User and bind mocked object to service container
     * @return User Mocked User
     */
    protected function getDBMock()
    {
        $app = app();
        $dbMock = $this->getMockBuilder(DatabaseManager::class)
            ->setConstructorArgs([$app, $app['db.factory']])
            ->setMethods(['table', 'where', 'update'])
            ->getMock();

        app()->instance('db', $dbMock);

        return $dbMock;
    }

    /**
     * Mock User
     * @return User Mocked User
     */
    protected function getUserMock()
    {
        $userMock = $this->getMockBuilder(User::class)
            ->setMethods(['token'])
            ->getMock();

        return $userMock;
    }

    /**
     * Mock Auth Manager and bind mocked object to service container
     * @return AuthManager Mocked AuthManager
     */
    protected function getAuthMock()
    {
        $authMock = $this->getMockBuilder(AuthManager::class)
            ->setConstructorArgs([app()])
            ->setMethods(['check', 'user'])
            ->getMock();

        app()->instance('auth', $authMock);

        return $authMock;
    }


    /**
     * Mock Cookie and bind mocked object to service container
     * @return CookieJar Mocked CookieJar
     */
    protected function getCookieMock()
    {
    	$cookie = $this->getMockBuilder(CookieJar::class)
	    	->setMethods(['queue', 'forget'])
	    	->getMock();

    	app()->instance(CookieJar::class, $cookie);

    	return $cookie;
    }

    /**
     * Mock Rerquest and bind mocked object to service container
     * @return CookieJar Mocked CookieJar
     */
    protected function getRequestMock()
    {
        $request = $this->getMockBuilder(Request::class)
            ->setMethods(['cookie'])
            ->getMock();

        app()->singleton(Request::class, function($app) use($request) {
        	return $request;
        });

        return $request;
    }

    /**
     * Mock API Consumer
     * @param  [type] $is_successfull_response [description]
     * @param  array  $response                [description]
     * @return [type]                          [description]
     */
    private function mockConsumer($is_successfull_response, array $response = []) {
    	// Mock Response
    	$responseMock = $this->getMockBuilder(Illuminate\Http\Response::class)
						->setMethods(['isSuccessful', 'getContent'])
						->getMock();

		$responseMock->expects($this->any())
					->method('isSuccessful')
					->willReturn($is_successfull_response);

		$responseMock->expects($this->any())
					->method('getContent')
					->willReturn(json_encode($response));

		// Mock Consumer
		$apiConsumer = $this->getMockBuilder(Optimus\ApiConsumer\Router::class)
						->setConstructorArgs([app(), app()['request'], app()['router']])
						->setMethods(['post'])
						->getMock();

		$apiConsumer->expects($this->any())
					->method('post')
					->willReturn($responseMock);

    	app()->singleton('apiconsumer', function($app) use($apiConsumer){
			return $apiConsumer;
		});
    }
}