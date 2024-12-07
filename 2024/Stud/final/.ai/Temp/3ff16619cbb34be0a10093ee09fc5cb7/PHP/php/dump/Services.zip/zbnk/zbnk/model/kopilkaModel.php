<?php

namespace Model;

use Ramsey\Uuid\Uuid;
use Lib\SQLDispatcher;

class Kopilka {
    private static string $table = "kopilkas";

    private ?string $uuid = null;

    private string $owner_uuid;

    private string $title;
    private string $description;

    private float $goal;
    private float $current_balance;

    public function __construct(string $uuid, string $owner_uuid, string $title, string $description, int $goal, int $current_balance)
    {
        $this->uuid = $uuid;
        $this->owner_uuid = $owner_uuid;
        $this->title = $title;
        $this->description = $description;
        $this->goal = $goal;
        $this->current_balance = $current_balance;
    }

    public static function create(string $owner_uuid, string $title, float $goal, string $description): ?self
    {
        $uuid = Uuid::uuid4();

        if (User::exists($owner_uuid) == null)
        {
            return null;
        }

        while (self::exists($uuid))
        {
            $uuid = Uuid::uuid4();
        }

        if ($goal <= 0)
        {
            return null;
        }

        if (SQLDispatcher::execute(
            'INSERT INTO '.self::$table.' (uuid, owner_uuid, title, description, goal, current_balance) VALUES ($1, $2, $3, $4, $5, 0)',
            array($uuid, $owner_uuid, $title, $description, $goal))
            )
        {
            return new self(
                $uuid,
                $owner_uuid,
                $title,
                $description,
                $goal,
                0
            );
        }

        return null;
    }

    public static function exists($uuid): ?self
    {
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT uuid, owner_uuid, title, description, goal, current_balance FROM $table WHERE uuid = '$uuid'");

        if ($data)
        {
            return new self(
                $data[0],
                $data[1],
                $data[2],
                $data[3],
                $data[4],
                $data[5]
            );
        }

        return null;
    }

    public static function getUserKopilkas($uuid){
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT uuid FROM $table WHERE owner_uuid = '$uuid'");

        if ($data) {
            return $data;
        }

        return null;
    }

    public function update(): bool
    {
        $table = self::$table;

        if (SQLDispatcher::execute(
            'UPDATE '.self::$table.' SET (owner_uuid, title, description, goal, current_balance) = ($2, $3, $4, $5, $6) WHERE uuid = $1',
            array($this->uuid, $this->owner_uuid, $this->title, $this->description, $this->goal, $this->current_balance))
            )
        {
            return true;
        }

        return false;
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function getOwnerUuid(): string
    {
        return $this->owner_uuid;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getGoal(): string
    {
        return $this->goal;
    }

    public function getBalance(): string
    {
        return $this->current_balance;
    }

    public function json()
    {
        return json_encode([
            "title"           => $this->title,
            "description"     => $this->description,
            "goal"            => $this->goal,
            "current_balance" => $this->current_balance
        ]);
    }

    public function getMinimumDeposit(): float
    {
        return $this->goal * 0.05;
    }

    public function setCurrentBalance($current_balance): void
    {
        $this->current_balance = $current_balance;
    }
}
