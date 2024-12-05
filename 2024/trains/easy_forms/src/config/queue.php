<?php

return [

    'default' => env('QUEUE_CONNECTION', 'database'),
    'connections' => [
        'sync' => [
            'driver' => 'sync',
        ],
        'database' => [
            'driver' => 'mongodb',
            'connection' => 'mongodb-job',
            'table' => 'jobs',
            'queue' => 'default',
            'expire' => 60,
        ],
    ],
    'batching' => [
        'database' => env('DB_CONNECTION', 'database'),
        'table' => 'job_batches',
    ],
    'failed' => [
        'driver' => 'mongodb',
        'database' => 'mongodb-job',
        'table' => 'failed_jobs',
    ],

];