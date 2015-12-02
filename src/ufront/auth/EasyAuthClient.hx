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
EasyAuthClient is a `UFAuthHandler` implementation that simply uses a `User` object from `EasyAuth` on the server.

The current user can be set with `setCurrentUser()`, or automatically set to the currently logged-in user with `InlineEasyAuthClientMiddleware`.

Please note the permission checks here would be very easy to bypass on the client side.
You should always include permission checks in your remoting APIs, as permission checks on the server can't be tampered with as easily.
**/
#if client
	class EasyAuthClient implements UFAuthHandler {
		/**
		The current `UFAuthUser`, if logged in.
		Will be null if they are not logged in.

		See `getCurrentUser()` to retrieve the current user typed as a `User` object rather than the `UFAuthUser` interface.

		Please note this will not make any API calls - `currentUser` must have been set previously using `setCurrentUser()`.
		It is recommended to use the `InlineEasyAuthClientMiddleware` middleware to set the user on the first page load.
		If `setCurrentUser()` has not been called yet, this will be null.
		**/
		public var currentUser(get,null):Null<UFAuthUser>;

		var _currentUser:Null<User>;

		/**
		Does the current user have super-user status?

		This means they either have the `EasyAuthPermissions.EAPCanDoAnything` permission.

		(Note: Unlike `ufront.auth.EasyAuth`, we do not have a concept of "setup mode" on the client side at this time.)
		**/
		public var isSuperUser(get,null):Bool = null;

		/** The current `HttpContext`, provided by injection. **/
		var context(default,null):HttpContext;

		/**
		Create a new EasyAuth handler.

		@param httpContext (injected) The context of the current request.
		**/
		@inject
		public function new( httpContext:HttpContext ) {
			this.context = httpContext;
		}

		public function isLoggedIn() {
			return (_currentUser!=null);
		}

		public function requireLogin() {
			if ( !isLoggedIn() ) throw HttpError.authError( ANotLoggedIn );
		}

		public function isLoggedInAs( user:UFAuthUser ) {
			var u = Std.instance( user, User );
			return isSuperUser || ( u!=null && _currentUser!=null && u.userID==_currentUser.userID );
		}

		public function requireLoginAs( user:UFAuthUser ) {
			if ( !isLoggedInAs(user) ) throw HttpError.authError( ANotLoggedInAs(user) );
		}

		public function hasPermission( permission:EnumValue ) {
			return isSuperUser || (_currentUser!=null && _currentUser.can(permission));
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
		Get the current user, typed as a `User`.

		Please note this will not make any API calls - `currentUser` must have been set previously using `setCurrentUser()`.
		It is recommended to use the `InlineEasyAuthClientMiddleware` middleware to set the user on the first page load.
		If `setCurrentUser()` has not been called yet, this will return null.
		**/
		public function getCurrentUser():Null<User> {
			return _currentUser;
		}

		/**
		Set the current user.

		This should be done at the start of each request.

		You can use `InlineEasyAuthClientMiddleware` to set it automatically by getting the current user from `EasyAuthApi.getCurrentUser()`.
		**/
		public function setCurrentUser( u:Null<User> ):Null<User> {
			return _currentUser = u;
		}

		function get_currentUser() return _currentUser;

		/**
		Return a String representing the current auth handler.
		Will be `EasyAuth` if not logged in, or `EasyAuth[$userID]` if they are logged in.
		**/
		public function toString() {
			return 'EasyAuthClient' + (_currentUser!=null ? '[${_currentUser.userID}]' : "");
		}

		function get_isSuperUser() {
			if ( isSuperUser==null )
				isSuperUser = _currentUser!=null && _currentUser.can(EAPCanDoAnything);
			return isSuperUser;
		}
	}
#end
