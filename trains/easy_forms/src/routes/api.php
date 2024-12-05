<?php

use App\Http\Controllers\AdminFormIntegrationController;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AdminFormController;
use App\Http\Controllers\AdminFormInputController;
use App\Http\Controllers\AdminFormResultController;
use App\Http\Controllers\Debug\DebugController;
use App\Http\Controllers\FormController;

Route::controller(AuthController::class)->prefix('auth')->group(function () {
    Route::post('/register', 'register');
    Route::get('/me', 'me');
    Route::post('/login', 'login');
    Route::post('/logout', 'logout');
    Route::post('/refresh', 'refresh');
});

Route::middleware(['auth:api'])->prefix('admin')->group(function () {
    Route::apiResource('forms', AdminFormController::class);
    Route::apiEmdedResource('forms.inputs', AdminFormInputController::class);
    Route::apiEmdedResource('forms.integrations', AdminFormIntegrationController::class);
    Route::controller(AdminFormResultController::class)->group(function() {
        Route::get('/forms/{form}/results', 'index');
        Route::delete('/forms/{form}/results/{result_id}', 'destroy');
    });


});

Route::middleware(['auth:api'])->prefix('debug')->group(function () {
    Route::controller(DebugController::class)->group(function () {
        Route::get('/forms', 'forms');
    });
});

Route::controller(FormController::class)->prefix('forms')->group(function () {
    Route::get('/{form}', 'index');
    Route::post('/{form}', 'submit');
});