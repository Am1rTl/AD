<?php

use Illuminate\Support\Str;

return [
    'default' => env('DB_CONNECTION'),
    'connections' => [
        'mongodb' => [
            'driver' => 'mongodb',
            'dsn' => env('DB_URI'),
            'database' => 'easy_forms',
        ],
        'mongodb-job' => [
            'driver' => 'mongodb',
            'dsn' => env('DB_URI'),
            'database' => 'easy_forms_queue',
        ],   
    ]
];
