<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'email' => 'required|email|unique:users,email|max:255',
            'username' => 'required|string|max:128',
            'password' => 'required|string|max:128',
        ];
    }

}
