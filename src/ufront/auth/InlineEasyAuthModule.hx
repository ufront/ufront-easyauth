package ufront.auth;

import ufront.web.context.HttpContext;
import ufront.app.UFMiddleware;
import ufront.app.HttpApplication;
import tink.CoreApi;
import ufront.core.Sync;
import ufront.web.HttpError;
import tink.core.Error;

/**
	Allow for inline authentication on any HttpRequest.

	It will:

	 - Check if you are already logged in
	 - If not, check for `username` and `password` in either `request.authorization` or `request.params` and attempt to authenticate with these.
	 - `request.authorization` values will have precedence over values from `request.params`.
	 - Currently only works with EasyAuth as the AuthHandler, and EasyAuthDBAdapter as the AuthAdapter.  This may be more flexible in future

	@author Jason O'Neil
**/
#if server
class InlineEasyAuthModule implements UFRequestMiddleware
{
	public function new() {}

	public function requestIn( ctx:HttpContext ):Surprise<Noise,Error> {
		var t = Future.trigger();

		var s = ctx.session;
		var a = ctx.auth;

		// Wait for the session to init() - it might not have if they don't have InlineSessionMiddleware enabled
		ctx.session.init().handle( function(res) {

			// See if there is an already active session
			var isLoggedIn = false;
			switch res {
				case Success(_):
					if ( a.isLoggedIn() ) {
						isLoggedIn = true;
						t.trigger( Success(Noise) );
					}
				case Failure(err):
					// Session failed to start... weird, but we'll continue anyway.  Log the error.
					ctx.ufError( 'Failed to start session: $err' );
			}

			if ( !isLoggedIn ) {
				var attemptedLogin = false;
				if ( Std.is(a,EasyAuth) ) {
					var ea = cast a;
					var httpAuth = ctx.request.authorization;
					var params = ctx.request.params;

					var username:String = params['username'];
					var password:String = params['password'];

					if ( httpAuth!=null ) {
						username = httpAuth.user;
						password = httpAuth.pass;
					}

					if ( username!=null && password!=null ) {
						var surprise = ea.startSession( new EasyAuthDBAdapter(username, password) );
						surprise.handle( function (outcome) switch(outcome) {
							case Success(u):
								ctx.ufTrace( 'Logged in as $username ($u) inline' );
								t.trigger( Success(Noise) );
							case Failure(e):
								// Their login failed.  Even though this is inline and they may not need auth
								// for their request, they attempted to log in with incorrect credentials,
								// therefore give an error.
								ctx.ufError( 'Failed to log in as $username: $e' );
								t.trigger( Failure(HttpError.unauthorized()) );
						});
						attemptedLogin = true;
					}

				}
				if ( !attemptedLogin )
					// No login was attempted, just continue with the request
					t.trigger( Success(Noise) );
			}
		});

		return t.asFuture();
	}
}
#end