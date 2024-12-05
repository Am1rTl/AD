<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class DebugFormsRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'limit' => 'sometimes|required|int',
        ];
    }
}
