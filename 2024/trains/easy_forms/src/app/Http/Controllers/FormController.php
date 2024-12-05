<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Traits\EntityLimitTrait;
use App\Http\Requests\FormSubmitRequest;
use App\Jobs\HandleFormIntegrationsJob;
use App\Models\Form;
use App\Models\FormResult;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Routing\Controller;

class FormController extends Controller
{
    use EntityLimitTrait;

    public function index(Form $form): Form
    {
        $this->formPublicationCheck($form);
        return $form->makeHidden(['integrations']);
    }

    public function submit(Form $form, FormSubmitRequest $request): FormResult
    {
        $this->formPublicationCheck($form);
        $inputs = $request->safe()->input('inputs');

        $builder = $form->results();
        $this->entityLimitValidation($builder);

        $formResult = new FormResult();
        foreach ($inputs as $key => $value) {
            $formResult->{$key} = $value;
        }
        $builder->save($formResult);
        
        $this->dispatchIntegrations($form, $formResult);

        return $formResult;
    }

    private function dispatchIntegrations(Form $form, FormResult $formResult): void
    {
        $shouldDispatch = false;
        foreach ($form->integrations as $integration) {
            if ($integration->active) {
                $shouldDispatch = True;
                break;
            }
        }

        if ($shouldDispatch) {
            HandleFormIntegrationsJob::dispatch($form, $formResult);
        }        
    }

    // @todo: override binding
    private function formPublicationCheck(Form $form): void
    {
        if (!$form->published) {
            throw (new ModelNotFoundException)->setModel($form::class, $form->_id);
        }
    }
}
