package ufront.auth;

import ufront.web.session.*;
import ufront.easyauth.model.*;
import ufront.auth.model.*;
import ufront.auth.*;
import ufront.auth.PermissionError;
import hxevents.Dispatcher;
import hxevents.Notifier;
import ufront.web.context.HttpContext;
using tink.core.types.Outcome;
import thx.error.NullArgument;

/**
	
**/
#if server
	class EasyAuth implements IAuthHandler<User>
	{
		/**
			Create an EasyAuth AuthHandler.

			This is basically the same as the constructor, but makes for easy binding, especially helpful when passing to `HttpContext.create`
	
			For example, you can easily create a function that acts as an AuthHandler factory for each request:

			```
			var authFactory:HttpContext->IAuthHandler<IAuthUser> = EasyAuth.create.bind("mysessionname");
			```

			The result of this is cast as `IAuthHandler<IAuthUser>`, rather than the actual `EasyAuth`, so that it can be used with as an auth factory without casting, as "IAuthUser" and "User" are invariant in this case.
		**/
		public static inline function create( ?context:HttpContext, ?name:String ):IAuthHandler<IAuthUser> {
			return cast new EasyAuth( context, name );
		}

		/** Set to the number of seconds the session should last.  By default, value=0, which will end when the browser window/tab is closed. */
		public static var sessionLength:Int = 0;
		inline public static var DEFAULT_VARIABLE_NAME = "easyauth_session_storage"; 

		var _name:String;
		var context:HttpContext;

		public function new( context:HttpContext, ?name:String ) {
			_name = (name!=null) ? name : DEFAULT_VARIABLE_NAME;
			this.context = context;
		}
		
		public function isLoggedIn() {
			return session.exists(_name);
		}

		public function requireLogin() {
			if ( !isLoggedIn() ) throw NotLoggedIn("Not logged in");
		}

		public function isLoggedInAs( user:User ) {
			return currentUser!=null && currentUser.id==user.id;
		}

		public function requireLoginAs( user:User ) {
			if ( !isLoggedInAs(user) ) throw DoesNotHavePermission('Logged in as ${currentUser.username}, expected ${user.username}');
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
				throw DoesNotHavePermission('Permission $name not satisfied');
			}
		}

		public function requirePermissions( permissions:Iterable<EnumValue> ) {
			for ( p in permissions ) {
				requirePermission( p );
			}
		}

		public var session(get,null):IHttpSessionState;
		
		var _session:IHttpSessionState;
		function get_session() {
			if ( _session==null ) {
				_session = context.session;
				NullArgument.throwIfNull( _session );
			}
			return _session;
		}

		public var currentUser(get,null):User;

		var _currentUser:User;
		function get_currentUser() {
			if (_currentUser == null) {
				if (session.exists(_name)) {
					var userID:Null<Int> = session.get(_name);
					if (userID!=null) {
						_currentUser = User.manager.get( userID );
					}
				}
			}
			return _currentUser;
		}

		public function startSession( authAdapter:EasyAuthDBAdapter ):Outcome<User,PermissionError>
		{
			endSession();

			var result = authAdapter.authenticate();
			switch ( result ) {
				case Success(user):
					session.set(_name, user.id);
				case Failure(_):
			}

			return result;
		}

		public function endSession() {
			if (session.exists(_name)) session.remove(_name);
		}
	}
#end 
