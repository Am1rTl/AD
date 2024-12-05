<?php

namespace App\Providers;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        foreach (Config::get('form_integrations.types') as $type => $class) {
            $this->app->singleton($class, fn () => new $class);
            $this->app->alias($class, "form_integration:{$type}");
        }
    }

    public function boot(): void
    {
        Response::macro('message', function (string $message, int $status = 200) {
            return Response::json(['message' => $message], $status);
        });

        Route::macro('apiEmdedResource', function (string $name, string $controller, array $options = []) {
            return Route::apiResource($name, $controller, $options)->only(['store', 'update', 'destroy']);
        });
    }
}
