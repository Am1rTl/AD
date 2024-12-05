<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Traits\FiltredCollectionTrait;
use App\Http\Requests\FiltredAdminFormRequest;
use App\Models\Form;
use Illuminate\Routing\Controller;
use Illuminate\Support\Collection;

class AdminFormResultController extends Controller
{
    use FiltredCollectionTrait;

    public function index(Form $form, FiltredAdminFormRequest $request): Collection 
    {
        return $this->filtredCollection(
            $form->results()->orderByDesc('created_at')->get(),
            $request
        );
    }

    public function destroy(Form $form, string $result_id): void
    {
        $form->results()->where('_id', $result_id)->delete();
    }
}
