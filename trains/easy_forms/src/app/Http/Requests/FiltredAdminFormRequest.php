<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class FiltredAdminFormRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'filters' => 'sometimes|required|string',
        ];
    }
}
