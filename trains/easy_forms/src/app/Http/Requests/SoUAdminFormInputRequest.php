<?php

namespace App\Http\Requests;

use App\Enums\FormInputTypes;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class SoUAdminFormInputRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'type' => ['required', Rule::enum(FormInputTypes::class)],
            'name' => 'required|alpha_dash:ascii|max:255',
            'settings' => 'array|max:15',
            'settings.*' => 'array',
            'settings.*.*' => 'string',
            'style' => 'array|max:15',
            'style.*' => 'string',
        ];
    }
}
