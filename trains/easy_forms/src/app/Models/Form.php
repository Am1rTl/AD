<?php

namespace App\Models;

use MongoDB\Laravel\Eloquent\Model;
use MongoDB\Laravel\Relations\BelongsTo;
use MongoDB\Laravel\Relations\EmbedsMany;
use MongoDB\Laravel\Relations\HasMany;

class Form extends Model
{
    protected $fillable = [
        'title',
        'style',
        'published',
    ];

    public function inputs(): EmbedsMany
    {
        return $this->embedsMany(FormInput::class);
    }

    public function integrations(): EmbedsMany
    {
        return $this->embedsMany(FormIntegration::class);
    }

    public function results(): HasMany  
    {
        return $this->hasMany(FormResult::class);    
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
