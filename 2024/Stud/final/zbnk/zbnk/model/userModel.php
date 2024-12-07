<?php

namespace Model;

use Ramsey\Uuid\Uuid;
use Lib\SQLDispatcher;

class User
{
    private static string $table = "users";

    private ?string $uuid = null;
    private string $password;

    public function __construct($uuid, $password)
    {
        $this->uuid = $uuid;
        $this->password = $password;
    }

    public static function create($password): self|null
    {
        $uuid = Uuid::uuid4();
        $hashedPassword = hash('sha256', $password);
        $table = self::$table;

        while (self::exists($uuid)) {
            $uuid = Uuid::uuid4();
        }

        if (SQLDispatcher::execute(
            'INSERT INTO '.$table.' (uuid, password) VALUES ($1, $2)',
            array($uuid, $hashedPassword))
            )
        {
            return new self(
                $uuid,
                $hashedPassword
            );
        }

        return null;
    }

    public static function exists($uuid): ?self
    {
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT uuid, password FROM $table WHERE uuid = '$uuid'");

        if ($data)
        {
            return new self(
                $data[0],
                $data[1]
            );
        }

        return null;
    }

    public function login($password): bool
    {
        $hashedPassword = hash('sha256', $password);

        return (strcmp($this->password, $hashedPassword) == 0);
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }
}
