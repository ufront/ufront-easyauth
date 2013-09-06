package ufront.auth;

// import ufront.auth.storage.SessionStorage;
// import ufront.web.session.FileSession;
// import ufront.auth.IAuthAdapter;
// import ufront.auth.Auth;
// import ufront.auth.model.User;
// import ufront.auth.DBUserAuthAdapter;
// import ufront.auth.PermissionErrors;

// class UserAuth
// {
// 	#if server
// 		/** Require that a user is logged in.  Will throw DBUserAuthAdapter.NotLoggedIn if they are not. 

// 		You can pass a custom message in the error if desired. */
// 		public static function requireLogin(?msg:String)
// 		{
// 			if (isLoggedIn == false)
// 			{
// 				if (msg == null) msg = "You need to be logged in to do that...";
// 				throw NotLoggedIn(msg);
// 			}
// 		}

// 		/** Require that the user is authenticated and has a certain permission.  

// 		Will throw DBUserAuthError, either NotLoggedIn or DoesNotHavePermission if they do not.

// 		If the user does have permission, the code will continue to execute normally. 

// 		You can pass a custom message in the error if you desire. */
// 		public static function requirePermission(permission:EnumValue, ?msg:String)
// 		{
// 			requireLogin();
// 			if (user.can(permission) == false)
// 			{
// 				if (msg == null) 
// 				{
// 					var permissionName = Type.enumConstructor(permission);
// 					msg = 'You do not have the `$permissionName` permission required for this action.';
// 					throw DoesNotHavePermission(msg);
// 				}
// 			}
// 		}

// 		/** Require that a user has several different permissions. Essentially calls requirePermission() on each. */
// 		public static function requirePermissions(permissions:Iterable<EnumValue>, ?msg)
// 		{
// 			for (permission in permissions)
// 			{
// 				requirePermission(permission, msg);
// 			}
// 		}

// 		/** Set to the number of seconds the session should last.  By default, value=0, which will end at the end of the session. */
// 		public static var sessionLength:Int = 0;

// 		static var _sessionStorage:SessionStorage<User>;
// 		public static function getSession()
// 		{
// 			if (_sessionStorage == null)
// 			{
// 				_sessionStorage = new SessionStorage(FileSession.create(neko.Web.getCwd() + 'sessions', sessionLength));
// 			}
// 			return _sessionStorage;
// 		}

// 		static var _auth:Auth<User>;
// 		public static function getAuth()
// 		{
// 			if (_auth == null)
// 			{
// 				_auth = new ufront.auth.Auth<User>(getSession());
// 			}
// 			return _auth;
// 		}

// 		static var _user:User;
// 		public static function getUser()
// 		{
// 			if (_user == null)
// 			{
// 				if (getAuth().hasIdentity())
// 				{
// 					_user = getAuth().getIdentity();
// 				}
// 			}
// 			return _user;
// 		}

// 		public static function startSession(authAdapter:DBUserAuthAdapter)
// 		{
// 			var authResult = getAuth().authenticate(authAdapter);
// 			if (authResult.isvalid)
// 			{
// 				getSession().write(authResult.identity);
// 			}
// 			return authResult;
// 		}

// 		public static function endSession()
// 		{
// 			getAuth().clearIdentity();
// 		}


// 		public static var isLoggedIn(get,never):Bool;
// 		static function get_isLoggedIn()
// 		{
// 			return getAuth().hasIdentity() && getAuth().getIdentity() != null;
// 		}

// 		public static var user(get,never):User;
// 		static function get_user()
// 		{
// 			var auth = getAuth();
// 			if (auth.hasIdentity())
// 			{
// 				var user = auth.getIdentity();
// 				if (user != null) return user;
// 			}
// 			return null;
// 		}
// 	#end 
// }
