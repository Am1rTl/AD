<?php

use App\Models\Form;
use App\Models\FormInput;
use App\Models\FormIntegration;
use App\Models\FormResult;

return [

    'name' => env('APP_NAME'),
    'env' => env('APP_ENV'),
    'debug' => (bool) env('APP_DEBUG', false),
    'url' => env('APP_URL'),
    'timezone' => env('APP_TIMEZONE'),
    'locale' => env('APP_LOCALE'),
    'fallback_locale' => env('APP_FALLBACK_LOCALE', 'en'),
    'faker_locale' => env('APP_FAKER_LOCALE', 'en_US'),
    'cipher' => 'AES-256-CBC',
    'key' => env('APP_KEY'),
    'maintenance' => [
        'driver' => env('APP_MAINTENANCE_DRIVER', 'file'),
        'store' => env('APP_MAINTENANCE_STORE', 'database'),
    ],
    'entity_limits' => [
        Form::class => 10,
        FormInput::class => 15,
        FormIntegration::class => 2, 
        FormResult::class => 50,
    ]
];
