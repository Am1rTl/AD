<?php

namespace App\Http\Controllers\Traits;

use App\Http\Requests\FiltredAdminFormRequest;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

trait FiltredCollectionTrait
{
    protected function filtredCollection(Collection $collection, FiltredAdminFormRequest $request): Collection
    {
        $collection = $collection->keyBy('_id');
        $filters = json_decode($request->safe()->input('filters'), true);
        if (is_array($filters)) {
            foreach($filters as $filter) {
                $where = array_values((array)$filter);
                if (count($where) === 3 && $where[1] == 'search') {
                    [$attr, $_, $value] = $where;
                    $collection = $collection->filter(fn (Model $model) => Str::startsWith($model->{$attr}, $value));
                } elseif ($where) {
                    $collection = $collection->where(...$where);
                }
            }    
        }
        return $collection;
    }
}
