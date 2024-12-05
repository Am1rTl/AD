<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Str;

class ExternalUrl implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (!Str::isUrl($value, ['http', 'https'])) {
            $fail('The :attribute must be start at http or https.');
            return;
        } 

        $match = preg_match('#https?://([\d\.]+)/#', $value, $matches);
        if ($match > 0 && !$this->isExternalIp($matches[1])) {
            $fail('The :attribute must be external url.');
        }
    }

    private function isExternalIp(string $ip): bool
    {
        return (bool) filter_var(
            $ip, 
            FILTER_VALIDATE_IP, 
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE |  FILTER_FLAG_NO_RES_RANGE
        );
    }
}