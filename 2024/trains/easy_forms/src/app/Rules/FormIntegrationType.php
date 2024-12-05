<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Config;

final class FormIntegrationType implements ValidationRule
{
    private array $integratinos = []; 

    public function __construct()
    {
        $this->integratinos = array_keys(Config::get('form_integrations.types')); 
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (!in_array($value, $this->integratinos)) {
            $fail(sprintf('The :attribute must be one of [%s].', implode(',', $this->integratinos)));
        }
    }
}