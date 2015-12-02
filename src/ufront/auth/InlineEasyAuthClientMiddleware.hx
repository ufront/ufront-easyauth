package ufront.auth;

import ufront.MVC;
import ufront.auth.api.EasyAuthApi;
import ufront.auth.model.User;
import haxe.ds.Option;
import tink.CoreApi;
using ufront.core.AsyncTools;

/**
Middleware which will fetch the current `User` for `EasyAuthClient` to use on the first request, and keep it for future requests.

Please note this requires `EasyAuthApi` to be shared in the remoting API context on your server.

Also note that if a user's login status, or their permissions are updated on the server, this will not automatically be reflected on the client.
You will have to call `InlineEasyAuthClientMiddleware.updateCurrentUser()` to have the client be aware of the user's new permissions.

@author Jason O'Neil
**/
#if client
class InlineEasyAuthClientMiddleware implements UFRequestMiddleware implements UFInitRequired {
	static var userOption:Null<Option<User>>;
	static var apps:Array<ClientJsApplication> = [];

	public function new() {}

	public function init( app:HttpApplication ):Surprise<Noise,Error> {
		var clientApp = Std.instance( app, ClientJsApplication );
		if ( clientApp!=null )
			apps.push( clientApp );
		return SurpriseTools.success();
	}
	public function dispose( app:HttpApplication ):Surprise<Noise,Error> {
		var clientApp = Std.instance( app, ClientJsApplication );
		if ( clientApp!=null )
			apps.remove( clientApp );
		return SurpriseTools.success();
	}

	public function requestIn( ctx:HttpContext ):Surprise<Noise,Error> {
		var auth = Std.instance( ctx.auth, EasyAuthClient );
		if ( auth!=null ) {
			if ( userOption==null ) {
				try {
					var easyAuthApi = ctx.injector.getInstance( EasyAuthApiAsync );
					var surprise:Surprise<Null<User>,Error> = easyAuthApi.getCurrentUser();
					return surprise >> function (u:Null<User>) {
						userOption = (u!=null) ? Some(u) : None;
						setUser( auth );
						return Noise;
					}
				}
				catch ( e:Dynamic ) {
					return SurpriseTools.asSurpriseError( e, 'Failed to perform inline authentication' );
				}
			}
			else {
				setUser( auth );
				return SurpriseTools.success();
			}
		}
		else return SurpriseTools.success();
	}

	static function setUser( auth:EasyAuthClient ) {
		switch userOption {
			case Some(user):
				auth.setCurrentUser( user );
			case None:
				auth.setCurrentUser( null );
		}
	}

	/**
	Update the current user.

	The `ClientJsApplication.currentContext` auth will be updated to use the new user.
	The internal cache for this middleware will also be updated so future requests will use the new user.
	**/
	public static function updateCurrentUser( u:Null<User> ) {
		userOption = (u!=null) ? Some(u) : None;
		for ( clientApp in apps ) {
			var auth = Std.instance( clientApp.currentContext.auth, EasyAuthClient );
			if ( auth!=null )
				setUser( auth );
		}
	}
}
#end
