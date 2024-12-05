<?php

use App\Exceptions\ModelNotFoundExceptionDecorator;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        commands: __DIR__.'/../routes/console.php',
        api: __DIR__.'/../routes/api.php',
        apiPrefix: '/api',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->redirectGuestsTo(fn() => null);
        $middleware->redirectUsersTo(fn() => null);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        $exceptions->shouldRenderJsonWhen(fn() => true);
        $exceptions->map(ModelNotFoundException::class, function (ModelNotFoundException $e) {
            return (new ModelNotFoundExceptionDecorator)->setModel($e->getModel(), $e->getIds());
        });
    })->create();
