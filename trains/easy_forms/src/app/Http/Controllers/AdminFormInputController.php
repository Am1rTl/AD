<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Traits\EntityLimitTrait;
use App\Http\Requests\SoUAdminFormInputRequest;
use App\Models\Form;
use App\Models\FormInput;
use Illuminate\Http\Request;

class AdminFormInputController extends BaseAdminFormController
{
    use EntityLimitTrait;

    public function store(string $formId, SoUAdminFormInputRequest $request): Form
    {
        $form = $this->getForm($formId, $request);
        $builder = $form->inputs();
        $this->entityLimitValidation($builder);

        $input = new FormInput($request->validated());
        $builder->attach($input);
        return $form;
    }

    public function update(string $formId, string $inputId, SoUAdminFormInputRequest $request): Form
    {
        $form = $this->getForm($formId, $request);
        $input = $form->inputs()->find($inputId);
        if ($input) {
            $input->update($request->validated());
        }
        return $form;
    }

    public function destroy(string $formId, string $inputId, Request $request): Form
    {
        $form = $this->getForm($formId, $request);
        $form->inputs()->detach([$inputId]);
        return $form;
    }
}
