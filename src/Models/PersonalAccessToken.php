<?php

namespace Hanafalah\ApiHelper\Models;

use Laravel\Sanctum\Contracts\HasAbilities;
use Laravel\Sanctum\PersonalAccessToken as LaravelPersonalAccessToken;
use Hanafalah\LaravelHasProps\Concerns\HasProps;

class PersonalAccessToken extends LaravelPersonalAccessToken implements HasAbilities
{
    use HasProps;

    protected $fillable = [
        'id',
        'name',
        'tokenable_type',
        'tokenable_id',
        'token',
        'abilities',
        'last_used_at',
        'expires_at',
        'device_id'
    ];

    /**
     * Find the token instance matching the given token.
     *
     * @param  string  $token
     * @return static|null
     */
    public static function findToken($token)
    {        
        if (strpos($token, '|') === false) {
            return static::where('token', hash('sha256', $token))->firstOrFail();
        }

        [$id, $token] = explode('|', $token, 2);

        if ($instance = static::findOrFail($id)) {
            return hash_equals($instance->token, hash('sha256', $token)) ? $instance : null;
        }
    }
}
