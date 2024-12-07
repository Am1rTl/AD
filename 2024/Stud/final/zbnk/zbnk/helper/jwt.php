<?php

namespace Helper;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Model\User;

class JWTHelper {
    private static string $keyfile = '/app/key.txt';
    private static ?string $key = null;

    private static function set(): void
    {
        if (self::$key == null)
        {
            self::$key = file_get_contents(self::$keyfile);
        }
    }

    public static function validate_jwt($jwt): bool
    {
        self::set();

        $payload = self::parse_jwt_contents($jwt);
        return ((time() < $payload->exp)
                && self::validate_jwt_signature($payload, $jwt)
                && User::exists($payload->uuid) != null);
    }

    private static function validate_jwt_signature($init_payload, $jwt)
    {
        $pathToKeyFile = realpath($init_payload->kid);

        if (str_contains($pathToKeyFile, "dev/zero") || str_contains($pathToKeyFile, "dev/urandom"))
        {
            echo "Bad value";
            exit;
        }

        $payload = [
            'uuid' => $init_payload->uuid,
            'exp' => $init_payload->exp,
            'kid' => $init_payload->kid
            ];

        $key = file_get_contents($init_payload->kid);

        if (strval($jwt) === strval(JWT::encode($payload, $key, 'HS256')))
        {
            return true;
        } else {
            return false;
        }
    }

    public static function generate_jwt($uuid): ?string
    {
        self::set();
        $payload = [
            'uuid' => $uuid,
            'exp' => strval(strtotime('+60 minutes', time())),
            'kid' => self::$keyfile
        ];

        return JWT::encode($payload, self::$key, 'HS256');
    }

    public static function get_uuid_from_jwt($jwt): ?string
    {
        if ($_SERVER["REMOTE_ADDR"] === "127.0.0.1")
        {
            return 'admin';
        }

        if (!self::validate_jwt($jwt))
        {
            return null;
        }

        $payload = self::parse_jwt_contents($jwt);

        if (!User::exists($payload->uuid))
        {
            return null;
        }

        return $payload->uuid;
    }

    private static function parse_jwt_contents($jwt): mixed
    {
        $decoded_jwt = explode(".", $jwt);
        $payload = json_decode(base64_decode($decoded_jwt[1]));

        return $payload;
    }
}
