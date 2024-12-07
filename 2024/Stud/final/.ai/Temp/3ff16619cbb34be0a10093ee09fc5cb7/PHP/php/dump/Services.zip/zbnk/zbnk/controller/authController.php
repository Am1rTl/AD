<?php

use Model\User;
use Helper\JWTHelper;
use Model\Balance;

class AuthController {

    public static function reglog(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/index_logged.html");
            return;
        }

        echo file_get_contents("/app/views/login_reg.html");
    }

    public static function index(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/index_logged.html");
            return;
        }

        echo file_get_contents("/app/views/index.html");
    }

    public static function login(): void
    {
        if (!(isset($_POST["uuid"]) && isset($_POST["password"])))
        {
            echo "Error";
            return;
        }

        $uuid = strval($_POST["uuid"]);
        $password = strval($_POST["password"]);

        $user = User::exists($uuid);
        if ($user == null)
        {
            echo "Wrong credentials.";
            return;
        }

        if ($user->login($password))
        {
            setcookie('session', JWTHelper::generate_jwt($uuid),(time() + 31536000) , '/');
            header("Location: /");
            return;
        }

        echo "Wrong credentials.";
    }

    public static function register(): void
    {
        if (!isset($_POST["password"]))
        {
            echo "Error";
            return;
        }

        $password = strval($_POST["password"]);

        $user = User::create($password);

        $balance = Balance::create($user->getUuid());
        $balance->setBalance([
            "RUB" => 100,
            "VCN" => 0,
            "HAM" => 0
        ]);
        $balance->update();

        echo "Ваш логин:<br>" . $user->getUuid() . "<br><br>У вас есть 6 секунд, чтобы скопировать его" . "<script>setTimeout(function () {window.location.href = '/login';}, 6000);</script>";
    }

    public static function logout(): void
    {
        setcookie('session', "",(time() + 31536000) , '/');
        header("Location: /");
    }
}
