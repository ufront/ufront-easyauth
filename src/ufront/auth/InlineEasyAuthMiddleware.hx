package ufront.auth;

import ufront.web.context.HttpContext;
import ufront.app.UFMiddleware;
import ufront.auth.api.EasyAuthApi;
import tink.CoreApi;
using ufront.core.AsyncTools;

/**
Middleware which allows inline `EasyAuth` authentication during any HTTP request.

This can be useful for creating APIs, where a single request will need to include the login credentials as well as perform the action.

How it works:

- This will check for `username` and `password` in either `HttpRequest.authorization` or `HttpRequest.params` and attempt to authenticate with these.
- `HttpRequest.authorization` values will have precedence over values from `HttpRequest.params`.
- It will use `EasyAuthApi.attemptLogin()` to check the credentials.

Outcomes:

- If no login was attempted, or the user was already logged in, the request will continue.
- If the login is successful, the user will be logged in and the request will continue.
- If the login was not successful, an error will be thrown and the request will not be continued.

Notes:

- This middleware will not `init()` or `commit()` a session.
  Use `InlineSessionMiddleware` to ensure sessions are correctly initiated and commited.

@author Jason O'Neil
**/
#if server
class InlineEasyAuthMiddleware implements UFRequestMiddleware {
	public function new() {}

	public function requestIn( ctx:HttpContext ):Surprise<Noise,Error> {
		var httpAuth = ctx.request.authorization;
		var params = ctx.request.params;
		var username = (httpAuth!=null) ? httpAuth.user : params['username'];
		var password = (httpAuth!=null) ? httpAuth.pass : params['password'];
		if ( username!=null && password!=null && ctx.auth.isLoggedIn()==false ) {
			try {
				var easyAuthApi = ctx.injector.getInstance( EasyAuthApi );
				return easyAuthApi.attemptLogin( username, password ).changeSuccessToNoise();
			}
			catch ( e:Dynamic ) {
				return SurpriseTools.asSurpriseError( e, 'Failed to perform inline authentication' );
			}
		}
		else return SurpriseTools.success();
	}
}
#end
