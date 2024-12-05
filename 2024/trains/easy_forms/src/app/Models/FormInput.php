<?php

namespace App\Models;

use MongoDB\Laravel\Eloquent\Model;

class FormInput extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'type',
        'name',
        'settings',
        'style',
    ];
}
