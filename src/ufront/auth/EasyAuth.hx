package ufront.auth;

import ufront.easyauth.model.*;
import ufront.auth.model.*;
import ufront.auth.UFAuthAdapter;
import ufront.auth.AuthError;
import ufront.web.context.HttpContext;
using tink.CoreApi;
import thx.error.NullArgument;

/**
	
**/
#if server
	class EasyAuth implements UFAuthHandler<User>
	{
		/** The default variable name to save the User ID to in the current session. Default is `easyauth_session_storage`. **/
		public static var defaultSessionVariableName = "easyauth_session_storage"; 

		/**
			The session variable name for the current auth handler.
			If the dependency injector has a String with the name "easyAuthSessionVariableName", that value will be used.
			If not, `defaultSessionVariableName` will be used.
		**/
		public var sessionVariableName(default,null):String;
		
		/** The current HttpContext, should be provided by injection. **/
		@inject public var context(default,null):HttpContext;

		/** The current user, if logged in. Will be null if they are not logged in. **/
		public var currentUser(get,null):Null<User>;

		/**
			Create a new EasyAuth handler.
			You should usually create this using an `injector.instantiate(EasyAuth)` call so that dependency injection is handled correctly.
		**/
		public function new() {}

		/** Read configuration from injector after `context` has been injected. **/
		@post public function postInjection() {
			// Manually check for this injection, because if it's not provided we have a default - we don't want minject to throw an error.
			sessionVariableName =
				if ( context.injector.hasMapping(String,"easyAuthSessionVarName") )
					context.injector.getInstance( String, "easyAuthSessionVarName" )
				else defaultSessionVariableName;
		}
		
		public function isLoggedIn() {
			return context.session.exists(sessionVariableName);
		}

		public function requireLogin() {
			if ( !isLoggedIn() ) throw NotLoggedIn;
		}

		public function isLoggedInAs( user:UFAuthUser ) {
			var u = Std.instance( user, User );
			return ( u!=null && currentUser!=null && u.id==currentUser.id );
		}

		public function requireLoginAs( user:UFAuthUser ) {
			if ( !isLoggedInAs(user) ) throw NotLoggedInAs( user );
		}

		public function hasPermission( permission:EnumValue ) {
			return (currentUser!=null && currentUser.can(permission));
		}

		public function hasPermissions( permissions:Iterable<EnumValue> ) {
			for ( p in permissions ) {
				if ( !hasPermission(p) ) return false;
			}
			return true;
		}

		public function requirePermission( permission:EnumValue ) {
			if ( !hasPermission(permission) ) {
				var name = Type.enumConstructor(permission);
				throw NoPermission( permission );
			}
		}

		public function requirePermissions( permissions:Iterable<EnumValue> ) {
			for ( p in permissions ) {
				requirePermission( p );
			}
		}

		public function setCurrentUser( user:UFAuthUser ) {
			var u = Std.instance( user, User );
			if ( u!=null ) {
				_currentUser = u;
				context.session.set(sessionVariableName, (u!=null) ? u.id : null);
			}
			else throw 'Could not set the current user to $user, because that user is not a ufront.auth.model.User';
		}


		var _currentUser:User;
		function get_currentUser() {
			if ( _currentUser==null ) {
				if ( context.session.exists(sessionVariableName) ) {
					var userID:Null<Int> = context.session.get( sessionVariableName );
					if ( userID!=null ) {
						_currentUser = User.manager.get( userID );
					}
				}
			}
			return _currentUser;
		}

		public function startSession( authAdapter:UFAuthAdapter<User> ):Surprise<User,AuthError> {
			endSession();

			var resultFuture = authAdapter.authenticate();
			resultFuture.handle( function(r) {
				switch ( r ) {
					case Success(user):
						context.session.set( sessionVariableName, user.id );
					case Failure(_):
				}
			});

			return resultFuture;
		}

		public function startSessionSync( authAdapter:UFAuthAdapterSync<User> ):Outcome<User,AuthError> {
			endSession();

			var result = authAdapter.authenticateSync();
			switch result {
				case Success(user): 
					context.session.set( sessionVariableName, user.id );
				case Failure(_):
			}

			return result;
		}

		public function endSession() {
			if ( context.session.exists(sessionVariableName) ) {
				context.session.remove( sessionVariableName );
			}
		}

		/**
			Fetch the user by their username.  

			(Note well: username, not database row ID.)
		**/
		public function getUserByID( id:String ) {
			return User.manager.select( $username==id );
		}

		public function toString() {
			return 'EasyAuth' + (currentUser!=null ? '[${currentUser.userID}]' : "");
		}
	}
#end 
