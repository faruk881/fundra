<?php

namespace App\Http\Controllers;

use App\Http\Requests\UserLoginRequest;
use App\Http\Requests\UserRegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(UserRegisterRequest $request) {
        try {
            $fields = $request->validated();

            $fields['password'] = Hash::make($fields['password']); // hash na dilao choba

            $user = User::create($fields);

            return apiSuccess('New user created',$user);

        } catch( \Throwable $e) {
            return apiError($e->getMessage(),500);
        }
    }

    public function login(UserLoginRequest $request) {

        try {
            $user = User::where('email', $request->email)->first();




            if (! $user || ! Hash::check($request->password, $user->password)) {
                return apiError('Invalid credentials', 401);
            }


            $token = $user->createToken('auth_token')->plainTextToken;

            return apiSuccess('Login successful', [
                'name'  => $user->name,
                'email' => $user->email,
                'token' => $token,
            ]);
        } catch(\Throwable $e) {
            return apiError($e->getMessage(),500);
        }

    }
}
