<?php

namespace Model;

use Helper\CurrencyHelper;
use Lib\SQLDispatcher;

class Balance {
    private static string $table = "balances";
    private static array $currencies = array("RUB", "HAM", "VCN");

    private ?string $uuid = null;
    private float $balance_rub;
    private float $balance_ham;
    private float $balance_vcn;

    public function __construct($uuid, $balance_rub, $balance_ham, $balance_vcn)
    {
        $this->uuid = $uuid;
        $this->balance_rub = $balance_rub;
        $this->balance_ham = $balance_ham;
        $this->balance_vcn = $balance_vcn;
    }

    public static function create($uuid): ?self
    {
        $table = self::$table;

        if (User::exists($uuid) == null || self::exists($uuid) != null)
        {
            return null;
        }

        if (SQLDispatcher::execute(
            'INSERT INTO '.$table.' (user_uuid, rub, ham, vcn) VALUES ($1, 0, 0, 0)',
            array($uuid))
            )
        {
            return new self(
                $uuid,
                0,
                0,
                0,
            );
        }

        return null;
    }

    public static function exists($uuid): ?self
    {
        $table = self::$table;
        $data = SQLDispatcher::query("SELECT user_uuid, rub, ham, vcn FROM $table WHERE user_uuid = '$uuid'");

        if ($data)
        {
            return new self(
                $data[0],
                $data[1],
                $data[2],
                $data[3]
            );
        }

        return null;
    }

    public function update(): bool
    {
        $table = self::$table;

        if (SQLDispatcher::execute(
            'UPDATE '.$table.' SET (rub, ham, vcn) = ($2, $3, $4) WHERE user_uuid = $1',
            array($this->uuid, $this->balance_rub, $this->balance_ham, $this->balance_vcn))
            )
        {
            return true;
        }

        return false;
    }

    public function convert(string $from, string $to, float $amount): bool
    {
        $balance = $this->getBalance();

        if ($balance[$from] < $amount)
        {
            return false;
        }

        $result = CurrencyHelper::convert($from, $to, $amount);
        if ($result == null)
        {
            return false;
        }

        $balance[$from] -= $amount;
        $balance[$to] += $result;

        $this->setBalance($balance);

        return true;
    }

    public function setBalance(array $balance): void
    {
        $this->balance_rub = $balance['RUB'];
        $this->balance_ham = $balance['HAM'];
        $this->balance_vcn = $balance['VCN'];
    }

    public function getBalance(): array
    {
        return [
            'RUB' => $this->balance_rub,
            'HAM' => $this->balance_ham,
            'VCN' => $this->balance_vcn
            ];
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }
}
