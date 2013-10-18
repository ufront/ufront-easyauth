package ufront.auth;

import ufront.web.context.HttpContext;
import ufront.module.IHttpModule;
import ufront.application.HttpApplication;
import tink.CoreApi;
import ufront.core.AsyncCallback;
using Types;

/**
	Allow for inline authentication on any HttpRequest.

	It will:

	 - Check for a SessionID in the parameters.  If it exists and is a valid session, it will initialize it.
	 - Check for `username` and `password` in either `request.authorization` or `request.params` and attempt to authenticate with these.  `request.authorization` values will have precedence over values from `request.params`.

	@author Jason O'Neil
**/
class InlineEasyAuthModule implements IHttpModule
{
	public function new() {}

	public function init( app:HttpApplication ) {
		app.onBeginRequest.handle( initAuth );
	}

	function initAuth( ctx:HttpContext ) {
		var t = Future.trigger();

		var s = ctx.session;
		var a = ctx.auth;

		var sessionReady = ctx.session.init();
		sessionReady.handle( function(res) {
			
			// See if there is an already active session
			var isLoggedIn = false;
			switch res {
				case Success(_):
					if ( s.isActive() && a.isLoggedIn() ) {
						isLoggedIn = true;
						t.trigger( Completed );
					}
				case Failure(err):
					ctx.ufError( 'Failed to start session: $err' );
			}

			if ( !isLoggedIn ) {
				var attemptedLogin = false;
				a.ifIs( EasyAuth, function(ea) {
					var httpAuth = ctx.request.authorization;
					var params = ctx.request.params;

					var username:String = params['username'];
					var password:String = params['password'];

					if ( httpAuth!=null ) {
						username = httpAuth.user;
						password = httpAuth.pass;
					}

					if ( username!=null && password!=null ) {
						var f = ea.startSession( new EasyAuthDBAdapter(username, password) );
						f.handle( t.trigger.bind(Completed) );
						attemptedLogin = true;
					}

				});
				if ( !attemptedLogin )
					t.trigger( Completed );
			}
		});
		
		return t.asFuture();
	}

	public function dispose() {};
}