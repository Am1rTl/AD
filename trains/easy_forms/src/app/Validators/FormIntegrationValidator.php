<?php

namespace App\Validators;

use App\FormIntegrations\IntegrationInterface;
use Illuminate\Support\Facades\Validator as ValidatorFacade;
use Illuminate\Validation\Validator;

final class FormIntegrationValidator 
{
    private IntegrationInterface $integration;

    public function __construct(IntegrationInterface $integration)
    {
        $this->integration = $integration;
    }

    public function __invoke(Validator $validator) 
    {
        $rules = $this->integration->getRules();
        ValidatorFacade::make($validator->getData(), $rules)->validated();
        $validator->addRules($rules);
    }
}