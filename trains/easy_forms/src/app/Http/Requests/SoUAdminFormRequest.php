<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SoUAdminFormRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'published' => 'required|boolean',
            'title' => 'required|string|max:255',
            'style' => 'array|max:15',
            'style.*' => 'string',
        ];
    }
}
