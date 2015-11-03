package ufront.auth;

import ufront.easyauth.model.*;
import ufront.auth.model.*;
import ufront.auth.UFAuthAdapter;
import ufront.auth.AuthError;
import ufront.auth.EasyAuthPermissions;
import ufront.web.context.HttpContext;
import ufront.web.HttpError;
import tink.core.Error;
using tink.CoreApi;

/**
EasyAuth is a `UFAuthHandler` implementation that uses database tables `User`, `Group` and `Permission` to control logins and authentication checks.

EasyAuth depends on Ufront-ORM for interacting with the database, and so this class is only available on sys targets compiled with `-D server`.
You can use `EasyAuthApi` to interact with EasyAuth from the client.
**/
#if server
	class EasyAuth implements UFAuthHandler {
		/**
		The session variable name to use when saving the User ID to the current session.
		This will be used if no session name is provided with dependency injection when EasyAuth is instantiated.
		The default value is `easyauth_session_storage`.
		**/
		public static var defaultSessionVariableName = "easyauth_session_storage";

		/**
		The current `UFAuthUser`, if logged in.
		Will be null if they are not logged in.
		See `getCurrentUser()` to retrieve the current user typed as a `User` object rather than the `UFAuthUser` interface.
		**/
		public var currentUser(get,null):Null<UFAuthUser>;
		var _currentUser:User;

		/**
		Does the current user have super-user status?

		This means they either have the `EasyAuthPermissions.EAPCanDoAnything` permission, or the app is still in setup mode.

		Here setup mode means that nobody has the `EAPCanDoAnything` permission yet, so the app is still being setup.
		While in setup mode, every user is considered a super user and is allowed to do anything, regardless of permissions.
		Because of this, you should always set up a super user with the `EAPCanDoAnything` permission before making your app public.
		**/
		public var isSuperUser(get,null):Bool = null;

		/**
		The session variable name for the current EasyAuth instance.
		If the dependency injector has a `String` with the name "easyAuthSessionVariableName", that value will be used.
		If not, `EasyAuth.defaultSessionVariableName` will be used.
		**/
		var sessionVariableName(default,null):String;

		/** The current `HttpContext`, provided by injection. **/
		var context(default,null):HttpContext;

		/**
		Create a new EasyAuth handler.

		@param httpContext (injected) The context of the current request.
		@param sessionVariableName (injected, optional) The session variable name to use.
		  A String named `easyAuthSessionVariableName` from the injector will be used if available.
		  Otherwise `EasyAuth.defaultSessionVariableName` will be used.
		**/
		@inject(_,"easyAuthSessionVariableName")
		public function new( httpContext:HttpContext, ?sessionVariableName:String ) {
			this.httpContext = httpContext;
			this.sessionVariableName =
				if ( sessionVariableName!=null ) sessionVariableName
				else defaultSessionVariableName;
		}

		public function isLoggedIn() {
			return isSuperUser || context.session.exists(sessionVariableName);
		}

		public function requireLogin() {
			if ( !isLoggedIn() ) throw HttpError.authError( ANotLoggedIn );
		}

		public function isLoggedInAs( user:UFAuthUser ) {
			var u = Std.instance( user, User );
			return isSuperUser || ( u!=null && currentUser!=null && u.userID==currentUser.userID );
		}

		public function requireLoginAs( user:UFAuthUser ) {
			if ( !isLoggedInAs(user) ) throw HttpError.authError( ANotLoggedInAs(user) );
		}

		public function hasPermission( permission:EnumValue ) {
			return isSuperUser || (currentUser!=null && currentUser.can(permission));
		}

		public function hasPermissions( permissions:Iterable<EnumValue> ) {
			if ( isSuperUser ) return true;

			for ( p in permissions ) {
				if ( !hasPermission(p) ) return false;
			}
			return true;
		}

		public function requirePermission( permission:EnumValue ) {
			if ( !hasPermission(permission) ) {
				var name = Type.enumConstructor(permission);
				throw HttpError.authError( ANoPermission(permission) );
			}
		}

		public function requirePermissions( permissions:Iterable<EnumValue> ) {
			for ( p in permissions ) {
				requirePermission( p );
			}
		}

		/**
		Change the current user who is logged in.

		This required the current user to be logged in and have the `EasyAuthPermissions.EAPCanLogInAsAnotherUser` permission.
		This can be used to implement "login as another user" admin functionality, so expose it with care.
		**/
		public function setCurrentUser( user:User ) {
			requirePermission( EAPCanLogInAsAnotherUser );
			_currentUser = user;
			context.session.set(sessionVariableName, (user!=null) ? user.id : null);
			context.session.regenerateID();
		}

		/**
		Get the current user, typed as a `User`.

		This is identical to the `currentUser` property's getter, except that it returns the current user typed as a `User` rather than the `UFAuthUser` interface.

		If a session has not been initiated this will return null.
		**/
		public function getCurrentUser():Null<User> {
			if ( _currentUser==null ) {
				if ( context.session!=null && context.session.isReady() && context.session.exists(sessionVariableName) ) {
					var userID:Null<Int> = context.session.get( sessionVariableName );
					if ( userID!=null ) {
						_currentUser = User.manager.get( userID );
					}
				}
			}
			return _currentUser;
		}

		function get_currentUser() return getCurrentUser();

		/**
		Attempt to login with a given `UFAuthAdapter`.

		If the user was previously logged in as a different user, they will be logged out before attempting a new login.

		See `EasyAuthApi.attemptLogin()` for a simple username/password login mechanism based on `EasyAuthDBAdapter`.
		**/
		public function startSession( authAdapter:UFAuthAdapter<User> ):Surprise<User,TypedError<AuthError>> {
			endSession();

			var resultFuture = authAdapter.authenticate();
			resultFuture.handle( function(r) {
				switch ( r ) {
					case Success(user):
						_currentUser = user;
						context.session.set( sessionVariableName, user.id );
						context.session.regenerateID();
					case Failure(_):
				}
			});

			return resultFuture;
		}

		/**
		A synchronous version of `startSession`.
		**/
		public function startSessionSync( authAdapter:UFAuthAdapterSync<User> ):Outcome<User,TypedError<AuthError>> {
			endSession();

			var result = authAdapter.authenticateSync();
			switch result {
				case Success(user):
					_currentUser = user;
					context.session.set( sessionVariableName, user.id );
					context.session.regenerateID();
				case Failure(_):
			}

			return result;
		}

		/**
		End the current authentication session.

		This will remove the User ID from the current `UFHttpSession`, effectivey logging the user out.

		The `UFHttpSession` (including the cookie and other session variables) will continue, it is not ended by calling this function.
		**/
		public function endSession() {
			if ( context.session.exists(sessionVariableName) ) {
				context.session.remove( sessionVariableName );
			}
			_currentUser = null;
		}

		/**
		Fetch the user by their username.

		(Note: username, not database row ID.)
		@param id The username (Please note: not the user database ID).
		@return The `User` with a matching username, if they existed.
		**/
		public function getUserByID( username:String ):Null<User> {
			return User.manager.select( $username==username );
		}

		/**
		Return a String representing the current auth handler.
		Will be `EasyAuth` if not logged in, or `EasyAuth[$userID]` if they are logged in.
		**/
		public function toString() {
			return 'EasyAuth' + (currentUser!=null ? '[${currentUser.userID}]' : "");
		}

		function get_isSuperUser() {
			if ( isSuperUser==null ) {
				isSuperUser = currentUser!=null && currentUser.can(EAPCanDoAnything);
				#if server
					if ( isSuperUser==false ) {
						// If there are no super-users, then we are in a kind of "setup mode".
						// Basically, until you have setup a superuser, everybody is a superuser.
						// Otherwise you get stuck not being able to set things up because you don't have permission.
						var numSuperUsers =
							try Permission.manager.count( $permission==Permission.getPermissionString(EAPCanDoAnything) )
							catch ( e:Dynamic ) {
								if ( sys.db.TableCreate.exists(Permission.manager)==false ) 0;
								else throw HttpError.internalServerError('Unable to check if current user is a superuser',e);
							}
						if ( numSuperUsers==0 ) {
							isSuperUser = true;
							context.ufWarn( 'Please note you have not set up a super-user yet, so we are treating everybody(!) as a super-user, even visitors. Please set up a super-user (with the EAPCanDoAnything permission) ASAP.' );
						}
					}
				#end
			}
			return isSuperUser;
		}
	}

	/**
	EasyAuthAdminMode is a version of `EasyAuth` that you can use in situations where authentication checks aren't needed.

	It basically sets `isSuperUser` to true, so that every permission check always passes.

	This is useful for CLI tools, internal web-apps and other code that does not need authentication checks, but wants to work with existing EasyAuth code.

	Please note `currentUser` will always be null, but `isLoggedIn()`, `requireLogin()`, `requireLoginAs()` etc will always succeed / return true.
	**/
	class EasyAuthAdminMode extends EasyAuth {
		public function new() {
			super();
			this.isSuperUser = true;
		}

		override function get_currentUser() {
			return null;
		}
	}
#end
