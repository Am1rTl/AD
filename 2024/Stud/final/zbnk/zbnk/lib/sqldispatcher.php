<?php

namespace Lib;


class SQLDispatcher {
    public static $conn = null;
    public static $connstring;

    public static function connect(): bool
    {
        self::$conn = pg_connect(self::$connstring);

        return (self::$conn != null);
    }

    public static function query(string $query): ?array
    {
        if (!self::$conn)
        {
            self::connect();
        }

        $result = pg_query(self::$conn, $query);

        if ($result && pg_num_rows($result) > 0 && pg_num_rows($result) == 1)
        {
            return pg_fetch_array($result, 0, PGSQL_NUM);
        } elseif ($result && pg_num_rows($result) > 0 && pg_num_rows($result) > 1) {
            return pg_fetch_all($result, PGSQL_ASSOC);
        }

        return null;
    }

    public static function execute(string $statement, array $params): bool
    {
        if (!self::$conn)
        {
            self::connect();
        }

        return pg_query_params(self::$conn, $statement, $params) != null;
    }

    public static function end(): void
    {
        if (self::$conn)
        {
            pg_close(self::$conn);
        }
    }
}
?>
