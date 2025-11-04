<?php

namespace Hanafalah\ApiHelper\Middlewares;

use Hanafalah\ApiHelper\Facades;
use Closure;

class ApiAccess
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle($request, Closure $next)
    {
        try {
            Facades\ApiAccess::init()->accessOnLogin(function ($api_access) {
                //IF YOU HAVE ANY TODO CONCEPT
            });
        } catch (\Throwable $th) {
            //throw $th;
        }
        return $next($request);
    }
}
