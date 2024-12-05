<?php

namespace App\Http\Controllers;

use App\Models\Form;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

abstract class BaseAdminFormController extends Controller
{
    protected function getForm(string $formId, Request $request): Form 
    {
        $form = $request->user()->forms()->find($formId);
        if (!$form) {
            throw (new ModelNotFoundException)->setModel(Form::class, [$formId]);
        }
        return $form;
    }
}
