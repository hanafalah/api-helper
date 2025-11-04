<?php

namespace Hanafalah\ApiHelper\Validators;

use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Hanafalah\ApiHelper\{
    Exceptions
};

class JWTTokenValidator extends Environment
{
    private $auth;

    public function handle(): bool
    {
        $this->auth = $this->getDecoded();
        if ($this->isForToken()) {
            $this->authenticate();
        } else {
            $this->tokenValidator();
        }
        return true;
    }

    public function tokenValidator(): self
    {
        if (!Auth::check()) {
            $data = $this->auth->data ?? null;

            if (!$data) {
                throw new \Exception('Auth data is missing');
            }

            if (isset($data->id)) {
                $user = $this->UserModel()->findOrFail($data->id);
                Auth::login($user);
            } else {
                if (!is_string($data->username ?? null) || !is_string($data->password ?? null)) {
                    throw new \Exception('Invalid username or password format');
                }
                Auth::attempt([
                    "username" => $data->username,
                    "password" => $data->password
                ]);
            }
        }

        return $this;
    }


    /**
     * Validates the token of the current instance.
     *
     * @return self
     *
     * @throws \Hanafalah\ApiHelper\Exceptions\InvalidUsernameOrPassword
     */
    public function authenticate(): self
    {
        $this->user(function ($q) {
            foreach ($this->authorizationConfig()['keys'] as $key) {
                if (!isset($this->auth->data->{$key})) throw new Exception($key . ' not found in user data');
                $q->where($key, $this->auth->data->{$key});
            }
        });
        $validation = isset(static::$__api_user) && $this->checkingPassword();
        $validation = $this->additionalChecking($validation);
        if (!$validation) throw new Exceptions\InvalidUsernameOrPassword();
        return $this;
    }

    /**
     * Check if the given password matches the given hash.
     *
     * @param string $password The password to check.
     * @param string $hash The hash to compare with.
     *
     * @return bool True if the password matches the hash, otherwise false.
     */
    protected function checkingPassword(?string $password = null, ?string $hash = null): bool
    {
        $passName = $this->authorizationConfig()['password'];
        $password ??= $this->auth->data->{$passName};
        $hash     ??= self::$__api_user->{$passName};
        return Hash::check($password, $hash);
    }

    /**
     * Additional checking for the token.
     *
     * This function checks if the token have additional data, if yes then it will
     * check if the additional data is match with the additional data in the
     * api_access table.
     *
     * @param mixed $decoded_token The decoded token.
     * @param bool $validation The validation status.
     *
     * @return bool The validation status.
     */
    private function additionalChecking(bool $validation): bool
    {
        $api_access = $this->getApiAccess();
        if (isset($api_access->additional)) {
            foreach ($api_access->additional as $key => $value) {
                if (!isset($this->auth->data->{$key})) throw new Exceptions\UnauthorizedAccess;
                $validation &= $value == $this->auth->data->{$key};
                if (!$validation) throw new Exceptions\UnauthorizedAccess;
            }
        }
        return $validation;
    }
}
