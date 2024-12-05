<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('cleaner:form 30')
    ->withoutOverlapping()
    ->everyThirtyMinutes();