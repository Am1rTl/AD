<?php

namespace App\Models;

use MongoDB\Laravel\Eloquent\Model;
use MongoDB\Laravel\Relations\BelongsTo;

class FormResult extends Model
{
    protected $guarded = [];
    protected $perPage = 50;

    public function form(): BelongsTo
    {
        return $this->belongsTo(Form::class);
    }
}
