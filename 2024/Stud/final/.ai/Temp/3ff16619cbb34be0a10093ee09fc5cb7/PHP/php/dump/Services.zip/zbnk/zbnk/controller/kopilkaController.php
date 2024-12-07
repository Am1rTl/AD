<?php

use Helper\JWTHelper;
use Model\Kopilka;
use Model\User;
use Model\KopilkaMember;
use Model\Balance;

class KopilkaController {

    public static function kopilkalist(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/kopilka_list_join.html");
            return;
        }

        echo file_get_contents("/app/views/index.html");
    }

    public static function kopilkainfo(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/kopilka_info.html");
            return;
        }

        echo file_get_contents("/app/views/index.html");
    }

    public static function kopilkacreate(): void
    {
        if (isset($_COOKIE['session']) && JWTHelper::get_uuid_from_jwt($_COOKIE['session']) != null)
        {
            echo file_get_contents("/app/views/create_kopilka.html");
            return;
        }

        echo file_get_contents("/app/views/index.html");
    }

    public static function create(): void
    {
        if (!(isset($_POST["title"]) && isset($_POST["goal"]) && isset($_POST["goal"]) && isset($_COOKIE['session'])))
        {
            echo "Error";
            return;
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $title = $_POST["title"];
        $goal = $_POST["goal"];
        $description = $_POST["description"];

        $kopilka = Kopilka::create($user_uuid, $title, $goal, $description);
        if ($kopilka == null)
        {
            echo "Error";
            return;
        }

        $kopilka_uuid = $kopilka->getUuid();
        if (KopilkaMember::create($kopilka_uuid, $user_uuid, 0) == null)
        {
            echo "Error";
            return;
        }

        $user_path = "/app/reports/$user_uuid";
        $content = <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Таблица Копилок</title>
        </head>
        <body>
            <table border="1" cellspacing="0" cellpadding="5">
                <thead>
                    <tr>
                        <th>Название копилки</th>
                        <th>Описание</th>
                        <th>Цель</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>$title</td>
                        <td>$description</td>
                        <td>$goal</td>
                    </tr>
                </tbody>
            </table>
        </body>
        </html>
        HTML;

        system("mkdir $user_path");
        system("touch $user_path/$kopilka_uuid.html");

        $file = fopen("$user_path/$kopilka_uuid.html", 'w+');
        fwrite($file, $content);
        fclose($file);

        header("Location: /kopilka/list");
        echo json_encode(["uuid" => $kopilka_uuid]);
    }

    public static function get()
    {
        if (!(isset($_GET["uuid"]) && isset($_COOKIE['session'])))
        {
            echo "Error";
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $kopilka_uuid = $_GET['uuid'];

        $kopilka = Kopilka::exists($kopilka_uuid);

        if (($kopilka == null || KopilkaMember::exists($kopilka_uuid, $user_uuid) == null) && $user_uuid != 'admin')
        {
            echo "Access Denied";
            return;
        }
        header("Content-type: application/json");
        echo $kopilka->json();
    }

    public static function generate_report()
    {
        if (!(isset($_GET["uuid"]) && isset($_COOKIE['session'])))
        {
            echo "Error";
            return;
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $kopilka_uuid = strval($_GET['uuid']);
        $html_path = realpath("/app/reports/$user_uuid/$kopilka_uuid.html");
        $pdf_path = "/app/reports/$user_uuid/$kopilka_uuid.pdf";

        if (!str_starts_with($html_path, "/app/reports/") || !file_get_contents($html_path))
        {
            echo "No kopilka found!";
            return;
        }

        $command = "wkhtmltopdf $html_path $pdf_path > /dev/null 2>&1";
        exec($command);
        header("Content-Disposition: attachment; filename=report.pdf");
        echo file_get_contents($pdf_path);
    }

    public static function join()
    {
        if (!(isset($_POST["uuid"]) && isset($_POST["deposit"]))) {
            echo "Error";
            return;
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $kopilka_uuid = strval($_POST['uuid']);
        $deposit = floatval($_POST['deposit']);

        if (KopilkaMember::exists($kopilka_uuid, $user_uuid))
        {
            echo "You've already in";
            return;
        }

        $kopilka = Kopilka::exists($kopilka_uuid);
        if ($kopilka == null)
        {
            echo "Kopilka does not exist";
            return;
        }

        $user_balance = Balance::exists($user_uuid);
        $balance = $user_balance->getBalance();
        if ($kopilka->getMinimumDeposit() > $deposit && $balance['RUB'] > $deposit)
        {
            echo "Balance requirment is not met";
            return;
        }

        $balance['RUB'] -= $deposit;
        KopilkaMember::create($kopilka_uuid, $user_uuid, $deposit);
        $kopilka->setCurrentBalance($kopilka->getBalance() + $deposit);

        $user_balance->setBalance($balance);
        $user_balance->update();
        $kopilka->update();

        header("Location: /kopilka/list");
    }

    public static function userKopilkasList()
    {
        if (!(isset($_COOKIE['session'])))
        {
            echo "Error";
            return;
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $kopilkas = Kopilka::getUserKopilkas($user_uuid);

        if (count($kopilkas) == 1)
        {
            $kopilkas = ["uuid" => $kopilkas[0]];
            echo '[' . json_encode($kopilkas) . ']';
            return;
        }

        echo json_encode($kopilkas);
    }


    public static function userKopilkasJoinList()
    {
        if (!(isset($_COOKIE['session'])))
        {
            echo "Error";
            return;
        }

        $user_uuid = strval(JWTHelper::get_uuid_from_jwt($_COOKIE['session']));

        if ($user_uuid == null)
        {
            echo "Access Denied";
            return;
        }

        $kopilkas = KopilkaMember::get_kopilkas($user_uuid);

        if (count($kopilkas) == 1)
        {
            $kopilkas = ["uuid" => $kopilkas[0]];
            echo '[' . json_encode($kopilkas) . ']';
            return;
        }

        echo json_encode($kopilkas);
    }
}
