<?php

namespace App\Exceptions;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;

final class ModelNotFoundExceptionDecorator extends ModelNotFoundException 
{
    public function setModel($model, $ids = [])
    {
        if (Config::get('app.debug') === true) {
            return parent::setModel($model, $ids);
        } 

        $this->model = $model;
        $this->ids = Arr::wrap($ids);   
        $this->message = class_basename($model) . " not found"; 
        return $this;        
    }
}