<?php

use App\FormIntegrations\ApiHttpIntegration;
use App\FormIntegrations\MailIntegration;

return [
    'types' => [
        'api' => ApiHttpIntegration::class,
        'mail' => MailIntegration::class,
    ],
];