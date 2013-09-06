package ufront.auth;

import ufront.web.session.*;
import ufront.easyauth.model.*;
import ufront.auth.model.*;
import ufront.auth.*;
import ufront.auth.PermissionError;
import hxevents.Dispatcher;
import hxevents.Notifier;
using tink.core.types.Outcome;

/**
	
**/
#if server
	class EasyAuth implements IAuthHandler<User>
	{
		/** Set to the number of seconds the session should last.  By default, value=0, which will end when the browser window/tab is closed. */
		public static var sessionLength:Int = 0;
		inline public static var DEFAULT_VARIABLE_NAME = "easyauth_session_storage"; 

		/** Singleton instance **/
		public static var inst = new EasyAuth();

		var _name:String;

		public function new( ?name:String ) {
			_name = (name!=null) ? name : DEFAULT_VARIABLE_NAME;
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
			for (p in permissions) {
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
			for (p in permissions) {
				requirePermission( p );
			}
		}

		public var session(get,null):IHttpSessionState;
		
		var _session:IHttpSessionState;
		function get_session() {
			if (_session == null) {
				var cwd = #if php php.Web.getCwd() #elseif neko neko.Web.getCwd() #else Sys.getCwd() #end;
				_session = FileSession.create(cwd + 'sessions', sessionLength);
			}
			return _session;
		}

		public var currentUser(get,null):User;

		var _currentUser:User;
		function get_currentUser() {
			if (_currentUser == null) {
				if (session.exists(_name)) {
					var userID = session.get(_name);
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
