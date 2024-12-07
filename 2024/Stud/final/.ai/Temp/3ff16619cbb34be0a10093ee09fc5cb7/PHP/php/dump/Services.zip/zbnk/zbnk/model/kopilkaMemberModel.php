<?php

namespace Model;

use Lib\SQLDispatcher;

class KopilkaMember {
    private static string $table = "kopilkaMembers";

    private string $vault_uuid;
    private string $user_uuid;
    private float $deposit;

    public function __construct($vault_uuid, $user_uuid, $deposit)
    {
        $this->vault_uuid = $vault_uuid;
        $this->user_uuid = $user_uuid;
        $this->deposit = $deposit;
    }

    public static function create($kopilka_uuid, $user_uuid, $deposit): ?self
    {
        $table = self::$table;

        if (SQLDispatcher::execute(
            'INSERT INTO '.self::$table.' (vault_uuid, user_uuid, deposit) VALUES ($1, $2, $3)',
            array($kopilka_uuid, $user_uuid, $deposit))
            )
        {
            return new self(
                $kopilka_uuid,
                $user_uuid,
                $deposit
            );
        }

        return null;
    }

    public static function exists($kopilka_uuid, $user_uuid): self|null
    {
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT user_uuid, vault_uuid, deposit FROM $table WHERE vault_uuid = '$kopilka_uuid' AND user_uuid = '$user_uuid'");

        if ($data)
        {
            return new self(
                $data[0],
                $data[1],
                $data[2],
            );
        }

        return null;
    }

    public static function get_kopilkas($user_uuid)
    {
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT vault_uuid FROM $table WHERE user_uuid = '$user_uuid'");

        if ($data) {
            return $data;
        }

        return null;
    }
}
