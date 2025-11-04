<?php

namespace Hanafalah\ApiHelper\Concerns\Token;

use Laravel\Sanctum\HasApiTokens as SanctumHasApiTokens;
use Laravel\Sanctum\NewAccessToken;

trait HasApiTokens
{
    use SanctumHasApiTokens;

    protected string $__app_code;

    public function setAppCode(string $app_code): self{
        $this->__app_code = $app_code;
        return $this;
    }

    // /**
    //  * Create a new personal access token for the user.
    //  *
    //  * @param  string  $name
    //  * @param  array  $abilities
    //  * @param  \DateTimeInterface|null  $expiresAt
    //  * @return \Laravel\Sanctum\NewAccessToken
    //  */
    // public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null)
    // {
        // $time = time();
        // $data = [];
        
        // $auth_model = config('api-helper.authorization_model');
        // if ($auth_model['model'] !== $this::class) throw new \Exception("Model of `authorization_model` on `api-helper` config is not same with this model", 1);

        // foreach ($auth_model['keys'] as $column) $data[$column] = $this->{$column};

        // $api_access = ApiAccess::forToken()->setAppCode($this->__app_code ?? null);
        // $token = $api_access->encrypting($data);
        // return $this->setToken($name, $token, $abilities, $expiresAt);
    // }

    public function setToken(string $name, array $data, array $abilities = ['*'], $expiresAt = null): NewAccessToken
    {
        $expiresAt = $expiresAt
            ? (is_numeric($expiresAt)
                ? \Carbon\Carbon::createFromTimestampMs($expiresAt)
                : \Carbon\Carbon::parse($expiresAt))
            : now()->addDays(7);
        $token = $this->PersonalAccessTokenModel()->updateOrCreate([
            'tokenable_type' => $this->getMorphClass(),
            'tokenable_id'   => $this->getKey(),
            'name'           => $name,
            'device_id'      => $_SERVER['HTTP_DEVICE_ID'] ?? null
        ], [
            'token'      => hash('sha256', $data['plainTextToken']),
            'abilities'  => json_encode($abilities),
            'expires_at' => $expiresAt
        ]);
        if (count($data['props']) > 0) {
            foreach ($data['props'] as $key => $prop) $token->{$key} = $prop;
            $token->save();
        }
        return new NewAccessToken($token, $token->getKey() . '|' . $data['plainTextToken']);
    }

    public function token()
    {
        return $this->morphOneModel('PersonalAccessToken', 'tokenable');
    }
}
