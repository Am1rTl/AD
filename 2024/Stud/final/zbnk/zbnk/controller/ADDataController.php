<?php

use Lib\SQLDispatcher;

class ADDataController {
    public static function get() {
        $query = "
        SELECT
            u.uuid,
            json_agg(k.uuid) AS kopilkas
        FROM
            users u
        LEFT JOIN
            kopilkas k
        ON
            u.uuid = k.owner_uuid
        GROUP BY
            u.uuid;
    ";
        echo json_encode(SQLDispatcher::query($query), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
}
