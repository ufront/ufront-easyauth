package ufront.auth;

import ufront.web.session.*;
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
		/** Set to the number of seconds the session should last.  By default, value=0, which will end when the browser window/tab is closed. */
		public static var sessionLength:Int = 0;

		inline static var DEFAULT_VARIABLE_NAME = "easyauth_session_storage"; 

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
			if ( !isLoggedIn() ) throw NotLoggedIn;
		}

		public function isLoggedInAs( user:User ) {
			return currentUser!=null && currentUser.id==user.id;
		}

		public function requireLoginAs( user:User ) {
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

		public var session(get,null):UFHttpSessionState;
		
		var _session:UFHttpSessionState;
		function get_session() {
			if ( _session==null ) {
				_session = context.session;
				NullArgument.throwIfNull( _session );
			}
			return _session;
		}

		public var currentUser(get,set):User;

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
		function set_currentUser( u:User ) {
			_currentUser = u;
			session.set(_name, (u!=null) ? u.id : null);
			return u;
		}

		public function startSession( authAdapter:UFAuthAdapter<User> ):Surprise<User,AuthError> {
			endSession();

			var resultFuture = authAdapter.authenticate();
			resultFuture.handle( function(r) {
				switch ( r ) {
					case Success(user): 
						session.set(_name, user.id);
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
					session.set(_name, user.id);
				case Failure(_):
			}

			return result;
		}

		public function endSession() {
			if (session.exists(_name)) {
				session.remove(_name);
			}
		}

		/**
			Fetch the user by their username.  

			(Note well: username, not database row ID.)
		**/
		public function getUserByID( id:String ) {
			return User.manager.select( $username==id );
		}

		static var _factory:EasyAuthFactory;
		public static function getFactory( ?name:String ) {
			if ( _factory==null || _factory.name!=name ) 
				_factory = new EasyAuthFactory( name );
			
			return _factory;
		}
	}

	class EasyAuthFactory implements UFAuthFactory {
		public var name(default,null):Null<String>;

		public function new( ?name:String ) {
			this.name = name;
		}

		public function create( context:HttpContext ) {
			return cast new EasyAuth( context, name );
		}
	}
#end 
