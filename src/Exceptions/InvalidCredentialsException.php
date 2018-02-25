<?php

/**
 * Invalid User Credentials Exception
 * this exception will be converted to json response
 * formatted using JsonResponseBuilder
 *
 * @package  passport-auth-proxy
 * @author  <a7mad.sa3d.2014@gmail.com>
 * @version  1.0.0 First Release
 */

namespace Saad\Passport\Exceptions;

use Saad\JsonResponseBuilder\JsonResponseBuilder;
use \Exception;

class InvalidCredentialsException extends Exception
{
	public function __construct($message = null)
	{
		$message  = $message ?: 'Invalid Credentials';
		parent::__construct($message);
	}

	/**
	 * @codeCoverageIgnore
	 * @return Illuminate\Http\JsonResponse Response
	 */
	public function render()
	{
		return (new JsonResponseBuilder())
				->error($this->getMessage(), 401)
				->setMessage('Invalid Credentials!')
				->getResponse(401);
	}
}