<?php

namespace App\Http\Controllers\Traits;

use App\Exceptions\ModelLimitException;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\Config;

trait EntityLimitTrait
{
    protected function entityLimitValidation(Relation $builder): void  
    {
        $model = $builder->getRelated();
        $limits = Config::get('app.entity_limits.' . $model::class, 5);
        if ($builder->count() >= $limits) {
            throw new ModelLimitException($model, $limits);
        }
    }
}
