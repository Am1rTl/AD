<?php

use Helper\JWTHelper;
use Model\Balance;
use Model\User;

class CurrencyController {
    public static function currency(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/currency.html");
            return;
        }

        echo file_get_contents("/app/views/index.html");
    }

    public static function convert_currency(): void
    {
        if (!(isset($_POST["amount"]) && isset($_POST["cur_from"]) && isset($_POST["cur_to"]) && isset($_COOKIE['session'])))
        {
            echo "Error";
            return;
        }

        $amount = floatval($_POST['amount']);
        $cur_from = strval($_POST['cur_from']);
        $cur_to = strval($_POST['cur_to']);

        $uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $balance = Balance::exists($uuid);

        if (!$balance->convert($cur_from, $cur_to, $amount))
        {
            echo "Something went wrong";
            return;
        }

        $balance->update();

        header("Location: /balance");
        return;
    }

    public static function get_balance(): void
    {
        if (!isset($_COOKIE['session']))
        {
            echo "Error";
            return;
        }

        $uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $balance = Balance::exists($uuid);

        echo json_encode($balance->getBalance());
    }

    public static function exchange_rate()
    {
        $HAM = 40;
        $VCN = 35;
        $arr = array ('HAM'=>$HAM,'VCN'=>$VCN);

        echo json_encode($arr);
    }
}
