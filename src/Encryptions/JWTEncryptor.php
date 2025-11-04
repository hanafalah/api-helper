<?php

namespace Hanafalah\ApiHelper\Encryptions;

use Firebase\JWT\{
    JWT,
    Key
};
use Hanafalah\ApiHelper\{
    Contracts\Encryptions\EncryptorInterface,
    Facades\ApiAccess
};
use Ramsey\Uuid\Uuid;
use stdClass;

class JWTEncryptor extends Environment implements EncryptorInterface
{
    protected $__rsJwtHeaders;

    private $__jwt_payload = [
        'iss'  => null,  // Issuer
        'aud'  => null,  // Audience
        'iat'  => null,  // Issued at (time the token is issued)
        'exp'  => null,  // Expiration time (1 hour from now)
        'sub'  => null,  // Subject (user or entity the token refers to)
        'jti'  => null,  // JWT ID (unique identifier for the token)
        'data' => []     // Custom claims (application-specific data)
    ];

    /**
     * Constructor method.
     *
     * When this class is instantiated, we set
     * the payload values to the current time, 
     * a unique identifier, and any custom 
     * payload values that may have been set.
     *
     * @return void
     */
    public function __construct()
    {
        $this->__rsJwtHeaders = new stdClass();
        self::$__payload ??= [];
    }

    /**
     * Handle the encryption process based on the algorithm set
     * in the ApiAccess instance.
     *
     * @return mixed
     */
    public function handle(): mixed
    {
        $this->setAlgorithm($this->getApiAccess()->algorithm);
        try {
            switch (self::$__algorithm) {
                case 'RS256':
                case 'RS384':
                case 'RS512':
                    $result = $this->setRsKeys()->processRS();
                break;
                case 'ES256':
                case 'ES384':
                case 'ES512':
                    $result = $this->setEsKeys()->processES();
                break;
                case 'HS256':
                case 'HS384':
                case 'HS512':
                    $result = $this->setSecretKey()->processHS();
                break;
            }
            return $result;
        } catch (\Throwable $th) {
            abort(401);
            //throw $th;
        }
    }

    /**
     * Setups the payload values for the JWT token.
     *
     * @return self
     */
    public function setupJwtPayload(mixed $payload = null): self
    {
        $payload ??= self::$__payload;
        $time = time();
        $api_access_expiration = ApiAccess::expiration();
        $exp  = isset($api_access_expiration) ? $time + $api_access_expiration : null;
        $jti  = Uuid::uuid4()->toString();
        $this->__jwt_payload = $this->mergeArray($this->__jwt_payload, [
            'iss'  => $_SERVER['HTTP_REFERER'] ?? null,
            'aud'  => $_SERVER['HTTP_HOST'] ?? null,
            'iat'  => $time,
            'jti'  => $jti,
            'exp'  => $exp,
            'data' => (is_array($payload))
                ? array_merge($this->__jwt_payload['data'], $payload)
                : $payload
        ]);
        $this->setExpirationToken($exp)->setJTI($jti);
        return $this;
    }

    /**
     * Gets the header of the JWT token after it has been decrypted.
     *
     * @return stdClass The header of the JWT token.
     */
    protected function getRsJwtHeader()
    {
        return $this->__rsJwtHeaders;
    }

    /**
     * Encrypts or decrypts the JWT token, depending on the encrypt flag.
     *
     * @param string $key The secret key to use for encryption or decryption.
     *
     * @return string The JWT token after encryption or decryption.
     * @throws \Illuminate\Contracts\Encryption\DecryptException
     * @throws \Firebase\JWT\ExpiredException
     * @throws \Firebase\JWT\SignatureInvalidException
     * @throws \Firebase\JWT\BeforeValidException
     * @throws \DomainException
     */
    protected function process(string $key)
    {
        $leeway = 60; // misalnya 60 detik toleransi
        JWT::$leeway = $leeway; // Set leeway sebelum decode
        try {
            if ($this->__encrypt) {
                $this->setupJwtPayload();
                return JWT::encode($this->__jwt_payload, $key, static::$__algorithm);
            } else {
                return JWT::decode(self::$__payload, new Key($key, static::$__algorithm), $this->__rsJwtHeaders);
            }
        } catch (\Exception $e) {
            abort(401);
        }
    }

    /**
     * Set the JTI of the token in the database.
     *
     * @return self
     */
    protected function setJTI(string $jti): self
    {
        self::$__generated_token['jti'] = $jti;
        return $this;
    }
}
