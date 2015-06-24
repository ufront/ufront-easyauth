package ufront.auth;

import ufront.easyauth.model.*;
import ufront.auth.model.*;
import ufront.auth.UFAuthAdapter;
import ufront.auth.AuthError;
import ufront.auth.EasyAuthPermissions;
import ufront.web.context.HttpContext;
using tink.CoreApi;

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
			Does the current user have super-user status?

			This means they either have the EAPCanDoAnything permission, or nobody has that permission.
			What this means is, until you set a superuser, everyone will count as a superuser.
			This is potentially dangerous, but is required during the setup of your app.
		**/
		public var isSuperUser(get,null):Bool = null;

		/**
			Create a new EasyAuth handler.
			You should usually create this using an `injector.instantiate(EasyAuth)` call so that dependency injection is handled correctly.
		**/
		public function new() {}

		/** Read configuration from injector after `context` has been injected. **/
		@post public function postInjection() {
			// Manually check for this injection, because if it's not provided we have a default - we don't want minject to throw an error.
			sessionVariableName =
				if ( context.injector.hasMapping(String,"easyAuthSessionVariableName") )
					context.injector.getInstance( String, "easyAuthSessionVariableName" )
				else defaultSessionVariableName;
		}

		public function isLoggedIn() {
			return isSuperUser || context.session.exists(sessionVariableName);
		}

		public function requireLogin() {
			if ( !isLoggedIn() ) throw NotLoggedIn;
		}

		public function isLoggedInAs( user:UFAuthUser ) {
			var u = Std.instance( user, User );
			return isSuperUser || ( u!=null && currentUser!=null && u.id==currentUser.id );
		}

		public function requireLoginAs( user:UFAuthUser ) {
			if ( !isLoggedInAs(user) ) throw NotLoggedInAs( user );
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
				if ( context.session!=null && context.session.isActive() && context.session.exists(sessionVariableName) ) {
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

		public function asAuthHandler() return cast this;

		function get_isSuperUser() {
			if ( isSuperUser==null ) {
				isSuperUser = currentUser!=null && currentUser.can(EAPCanDoAnything);
				#if server
					if ( isSuperUser==false ) {
						// If there are no super-users, then we are in a kind of "setup mode".
						// Basically, until you have setup a superuser, everybody is a superuser.
						// Otherwise you get stuck not being able to set things up because you don't have permission.
						var numSuperUsers =
							try Permission.manager.count( $permission==Permission.getPermissionID(EAPCanDoAnything) )
							catch ( e:Dynamic ) {
								if ( sys.db.TableCreate.exists(Permission.manager)==false ) 0;
								else throw e;
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
		A version of EasyAuth that acts in admin mode, useful for task runners etc.

		Exactly the same, but `isSuperUser` is always true, so permissions checks always pass etc.
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
