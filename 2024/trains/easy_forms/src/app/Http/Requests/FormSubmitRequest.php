<?php

namespace App\Http\Requests;

use App\Rules\FormInput;
use Illuminate\Foundation\Http\FormRequest;

class FormSubmitRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'inputs' => 'required|array|max:15',
            'inputs.*' => ['required', new FormInput],
        ];
    }
}
