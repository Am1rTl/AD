<?php

namespace App\FormIntegrations;

use App\Models\FormIntegration;
use App\Models\FormResult;

interface IntegrationInterface 
{
    public function send(FormIntegration $integration, FormResult $formResult): void;
    public function getRules(): array;
}