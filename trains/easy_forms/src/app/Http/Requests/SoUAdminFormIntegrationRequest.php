<?php

namespace App\Http\Requests;

use App\Validators\FormIntegrationValidator;
use App\Rules\FormIntegrationType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\App;
use Illuminate\Validation\Validator;

class SoUAdminFormIntegrationRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'active' => 'required|boolean',
            'type' => ['required', 'string', new FormIntegrationType],
			'title' => 'required|string',
        ];
    }

    public function after(Validator $validator): FormIntegrationValidator
    {
        $integrationName = $validator->safe()->string('type');
        $integration = App::make("form_integration:{$integrationName}");
        return new FormIntegrationValidator($integration);
    }
}
