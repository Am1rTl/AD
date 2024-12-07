<?php

namespace Helper;

class CurrencyHelper {
    private static $currencies = ["RUB", "HAM", "VCN"];

    public static function convert(string $from, string $to, string $amount): ?float
    {
        if ((!in_array($from, self::$currencies)) || (!in_array($to, self::$currencies))) {
            return null;
        }

        switch ($from . $to) {
            case "RUBHAM":
                $result = $amount/40;
                break;
            case "HAMRUB":
                $result = $amount*40;
                break;
            case "VCNRUB":
                $result = $amount*35;
                break;
            case "RUBVCN":
                $result = $amount/35;
                break;
            case "VCNHAM":
                $result = $amount/1.142857;
                break;
            case "HAMVCN":
                $result = $amount/0.875;
                break;
        }

        return number_format((float)$result, 1, '.', '');;
    }
}
