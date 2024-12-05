<?php

namespace App\Http\Controllers\Debug;

use App\Http\Requests\DebugFormsRequest;
use App\Models\Form;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Response;

final class DebugController extends Controller
{
    public function forms(DebugFormsRequest $debugFormsRequest): mixed
    {
        if (!$debugFormsRequest->user()->can_debug) {
            return Response::message('Route not found', 404);
        }
        $limit = $debugFormsRequest->safe()->input('limit', 100);
        return Form::latest()->take($limit)->get();
    }
}