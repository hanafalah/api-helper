<?php

namespace Hanafalah\ApiHelper\Contracts;

use Hanafalah\ApiHelper\Contracts\Supports\BaseApiAccess;

interface ModuleApiAccess extends BaseApiAccess
{
  public function init(? string $authorization = null): self;
  public function accessOnLogin(?callable $callback = null): self;
  public function setEncryption($class): self;
  public function expiration(?int $custom = null): ?int;
  public function generateToken(?callable $callback = null): string;
  public function secure(callable $callback, array $middlewares = []): void;
}
