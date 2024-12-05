<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Traits\EntityLimitTrait;
use App\Http\Controllers\Traits\FiltredCollectionTrait;
use App\Http\Requests\FiltredAdminFormRequest;
use App\Http\Requests\SoUAdminFormRequest;
use App\Models\Form;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\Request;

class AdminFormController extends BaseAdminFormController
{
    use EntityLimitTrait;
    use FiltredCollectionTrait;

    public function index(FiltredAdminFormRequest $request): Collection
    {
        return $this->filtredCollection(
            $request->user()->forms()->orderByDesc('created_at')->get(),
            $request
        );
    }

    public function store(SoUAdminFormRequest $request): Form
    {
        $builder = $request->user()->forms();
        $this->entityLimitValidation($builder);

        $form = Form::create($request->validated());
        $builder->save($form);
        return $form;
    }

    public function show(string $formId, Request $request): Form
    {
        return $this->getForm($formId, $request);
    }

    public function update(string $formId, SoUAdminFormRequest $request): Form
    {
        $form = $this->getForm($formId, $request);
        $form->update($request->validated());
        return $form;
    }

    public function destroy(string $formId, Request $request): void
    {
        $form = $this->getForm($formId, $request);
        $form->delete();
    }
}
