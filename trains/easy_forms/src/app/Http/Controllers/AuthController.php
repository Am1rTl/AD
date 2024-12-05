<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Http\Requests\LoginRequest;
use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Response;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(RegisterRequest $request): User
    {  
        $validated = $request->validated();
        $user = User::create([
            'name' => $validated['username'],
            'email' => $validated['email'],
            'password' => $validated['password'],
        ]);
        return $user;
    }

    public function login(LoginRequest $request): array
    {
        $credentials = $request->validated();
        if (!$token = Auth::attempt($credentials)) {
            throw new AuthenticationException();
        }
        return $this->respondWithToken($token);
    }

    public function me(): User
    {
        return Auth::user();
    }

    public function logout(): JsonResponse
    {
        Auth::logout();
        return Response::message('Successfully logged out');
    }

    public function refresh(): array
    {
        return $this->respondWithToken(Auth::refresh());
    }    

    protected function respondWithToken(string $token): array
    {
        return [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60
        ];
    }
}
