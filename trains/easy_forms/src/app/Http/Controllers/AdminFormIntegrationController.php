<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Traits\EntityLimitTrait;
use App\Http\Requests\SoUAdminFormIntegrationRequest;
use App\Models\Form;
use App\Models\FormIntegration;
use Illuminate\Http\Request;

class AdminFormIntegrationController extends BaseAdminFormController
{
    use EntityLimitTrait;

    public function store(string $formId, SoUAdminFormIntegrationRequest $request): Form
    {
        $form = $this->getForm($formId, $request);
        $builder = $form->integrations();
        $this->entityLimitValidation($builder);

        $formIntegration = new FormIntegration($request->validated());
        $builder->attach($formIntegration);
        return $form;
    }

    public function update(string $formId, string $integrationId, SoUAdminFormIntegrationRequest $request): Form
    {
        $form = $this->getForm($formId, $request);
        $formIntegration = $form->integrations()->find($integrationId);
        if ($formIntegration) {
            $formIntegration->update($request->validated());
        }
        return $form;
    }

    public function destroy(string $formId, string $integrationId, Request $request): Form
    {
        $form = $this->getForm($formId, $request);
        $form->integrations()->detach([$integrationId]);
        return $form;
    }
}
