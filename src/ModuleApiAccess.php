<?php

namespace Hanafalah\ApiHelper;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Hanafalah\ApiHelper\Contracts\ModuleApiAccess as ContractsApiAccess;
use Hanafalah\ApiHelper\Schemas\Token;
use Hanafalah\ApiHelper\Supports\BaseApiAccess;

class ModuleApiAccess extends BaseApiAccess implements ContractsApiAccess
{
  public int $__expiration;
  public ?int $__expiration_config;

  /**
   * Initialize the API access by given request headers.
   * 
   * If the request has a token, it will be used to initialize the API access.
   * If the request has an app code, it will be used to initialize the API access.
   * If the request has a username, it will be used to initialize the API access.
   * If none of the above is true, an UnauthorizedAccess exception will be thrown.
   * 
   * @throws \Exceptions\UnauthorizedAccess
   * @return self
   */
  public function init(? string $authorization = null): self
  {
    $this->setCollectHeader();
    if (!request()->hasHeader('Authorization') && !isset($authorization)) throw new Exceptions\UnauthorizedAccess;
    $this->__expiration_config = config('api-helper.expiration');
    $this->expiration();
    if ($authorization == 'null') throw new Exceptions\UnauthorizedAccess;

    $authorization    ??= Str::replace('Bearer ', '', self::$__headers->get('Authorization'));
    if (is_numeric(Str::position($authorization, '|'))){
      self::$__access_token  = $this->PersonalAccessTokenModel()->findToken($authorization);
      $this->__authorization = explode('|', $authorization)[1];
    }else{
      $this->__authorization = $authorization;
    }
    //IF REQUEST HAS TOKEN
    switch (true) {
      case $this->hasAppCode() : $this->initByAppCode();break;
      case $this->hasToken()   : $this->initByToken();break;
      case $this->hasUsername(): $this->initByUsername();break;
      default: throw new Exceptions\UnauthorizedAccess;
    }
    return $this;
  }



  /**
   * Access the API on login.
   * 
   * This method is used to access the API after a user has successfully logged in.
   * It will check if the user has the correct role, and if the user has the correct
   * permission, it will call the given callback function.
   * 
   * @param callable $callback The callback function to be called if the user has the
   * correct role and permission.
   * 
   * @return self
   */
  public function accessOnLogin(?callable $callback = null): self
  {
    if (isset(self::$__decode_result->aud)){
      $validation = $this->forAuthenticate()->schemaContract('Token')->handle();
      if ($validation && isset($callback)) $callback($this);
    }
    return $this;
  }

  /**
   * Set the encryption method for generating the token.
   *
   * @param string $class The class of the encryption method.
   *
   * @return self
   */
  public function setEncryption($class): self
  {
    config([
      'api-helper.encryption' => $class
    ]);
    return $this;
  }

  /**
   * Set the expiration time for the token, in minutes.
   *
   * If $custom is set, it will override the default expiration time set in the
   * config file.
   *
   * @param int|null $custom The custom expiration time.
   *
   * @return int The expiration time in minutes.
   */
  public function expiration(?int $custom = null): ?int
  {
    if (isset($custom)) {
      config([
        'api-helper.expiration' => $custom
      ]);
    }
    $expiration = $custom ?? config('api-helper.expiration') ?? $this->__expiration_config ?? 3600*24;
    return $expiration;
  }

  /**
   * Generate token for API access.
   *
   * @return self
   */
  public function generateToken(?callable $callback = null): string
  {
    $token = $this->forToken()->useSchema(Token::class)->getClass()->handle();
    $this->setToken($token)->updateCounter();

    $props = ['app_code' => self::$__api_access->app_code];
    if (isset(self::$__generated_token['jti'])) $props['jti'] = self::$__generated_token['jti'];
    $data = [
      'plainTextToken' => $token,
      'props'          => $props
    ];
    $access_token = $this->getUser()->setToken($this->__token_access_name, $data, ['*'], self::$__generated_token['expires_at']);
    if (isset($callback)) {
      $callback($this);
    }
    return $access_token->plainTextToken;
  }

  public function secure(callable $callback, array $middlewares = []): void
  {
    $middlewares = $this->mergeArray(self::$__api_helper_config['middlewares'], $middlewares);
    Route::group([
      'middleware' => $middlewares
    ], function () use ($callback) {
      $callback();
    });

  }
}
