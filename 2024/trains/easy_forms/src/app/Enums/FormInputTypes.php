<?php

namespace App\Enums;

enum FormInputTypes: string
{
    case Text = 'text';
    case Radio = 'radio';
    case Checkbox = 'checkbox';
    case TextArea = 'textarea';
}