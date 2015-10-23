package ufront.auth.api;

import ufront.api.UFApi;
import ufront.auth.model.*;
import ufront.auth.AuthError;
import ufront.auth.EasyAuthDBAdapter;
import ufront.auth.EasyAuth;
import ufront.auth.EasyAuthPermissions;
import ufront.db.DatabaseID;
import minject.Injector;
import tink.core.Error;
import ufront.web.HttpError;
using ufront.core.AsyncTools;
using tink.CoreApi;
using Lambda;

/**
An API to conduct basic auth operations, from logging in to creating users and granting permissions.

Any operations in this API that might require special permissions will use the `EasyAuthPermissions` enum to check the current user's permissions.
**/
class EasyAuthApi extends UFApi {

	#if server
		@inject public var easyAuth:EasyAuth;
		@inject public var injector:Injector;
	#end

	/**
	Login and begin a session with the given username and password.

	By default this will use `EasyAuthDBAdapter` to attempt to match the username and password to a valid user.
	If you wish to use a different auth adapter to check a username and password in a different way, you can inject a different `ufront.auth.UFAuthAdapter<ufront.auth.model.User>` class.
	The custom `UFAuthAdapter` will be instantiated by dependency injection, and have both "username" and "password" mapped as Strings.
	See `EasyAuthDBAdapter` for an example implementation.

	@param username The username of the user we wish to log in as.
	@param password The user entered password - this will be hashed with the same salt and compared to the hash in the database.
	@return A `Surprise`: `Success(user)` if the login was successful, or `Failure(AuthError)` if it failed.
	**/
	public function attemptLogin( username:String, password:String ):Surprise<User,TypedError<AuthError>> {
		try {
			var authAdapter = getAuthAdapter( username, password );
			return easyAuth.startSession( authAdapter );
		}
		catch ( e:Dynamic ) {
			var authError = ALoginFailed('Failed to attempt login: $e');
			var error = Error.typed(500, 'Login Failed (Server Error)', authError);
			return error.asBadSurprise()
		}
	}

	function getAuthAdapter( username:String, password:String ):UFAuthAdapter<User> {
		var childInjector = injector.createChildInjector();
		childInjector.map( String, "username" ).toValue( username );
		childInjector.map( String, "password" ).toValue( password );
		if ( childInjector.hasMapping("ufront.auth.UFAuthAdapter<ufront.auth.model.User>")==false ) {
			childInjector.map( "ufront.auth.UFAuthAdapter<ufront.auth.model.User>" ).toClass( EasyAuthDBAdapter );
		}
		return childInjector.getValue( "ufront.auth.UFAuthAdapter<ufront.auth.model.User>" );
	}

	/**
	Logout (end the current session).

	Please note this does not end the session, the `UFHttpSession` will still be active, along with any cookies etc.
	Please note the session must be ready to use (having `HttpSession.init()` complete succesfully).
	It just removes the User ID from the session, effectively logging you out.
	**/
	public function logout():Void {
		easyAuth.endSession();
	}

	/**
	Check if a given username or password authenticates to a valid user.
	This does not initiate a session, but simply returns `true` or `false` if the credentials are valid.
	In production sending credentials to the server multiple times should be avoided, for general use you should use sessions and `this.attemptLogin()` instead.

	The `UFAuthAdapter` will be fetched using dependency injection using the same process described in `this.attemptLogin()`.

	@param username The username for attempted authentication.
	@param password The password for attempted authentication.
	@return A `Future<Bool>`, with `true` if username and password are valid, `false` otherwise.
	**/
	public function authenticate( username:String, password:String):Future<Bool> {
		var authAdapter = getAuthAdapter( username, password );
		return authAdapter.authenticate().map(function(outcome) return switch outcome {
			case Success(data): return true;
			case Failure(_): return false;
		});
	}

	/**
	Get a specific `User` object based on a database ID.
	This requires the `EasyAuthPermissions.EAPListAllUsers` permission.
	**/
	public function getUser( userID:DatabaseID<User> ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.get( userID );
		});
	}

	/**
	Get a specific `User` object based on the username.
	This requires the `EasyAuthPermissions.EAPListAllUsers` permission.
	**/
	public function getUserByUsername( username:String ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.select( $username==username );
		});
	}

	/**
	Get a list of all `User` objects in the database.
	This requires the `EasyAuthPermissions.EAPListAllUsers` permission.
	**/
	public function getAllUsers():Outcome<List<User>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.all();
		});
	}

	/**
	Get a specific `Group` object based on a database ID.
	This requires the `EasyAuthPermissions.EAPListAllGroups` permission.
	**/
	public function getGroup( groupID:DatabaseID<Group> ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.get( groupID );
		});
	}

	/**
	Get a specific `Group` object based on the group name.
	This requires the `EasyAuthPermissions.EAPListAllGroups` permission.
	**/
	public function getGroupByName( name:String ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.select( $name==name );
		});
	}

	/**
	Get a list of all `Group` objects in the database.
	This requires the `EasyAuthPermissions.EAPListAllGroups` permission.
	**/
	public function getAllGroups():Outcome<List<Group>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.all();
		});
	}

	/**
	Get a list of all groups for a given user.
	This requires the `EasyAuthPermissions.EAPListGroupsForUser` permission.
	**/
	public function getAllGroupsForUser( userID:DatabaseID<User> ):Outcome<List<Group>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListGroupsForUser );
			var user = User.manager.get( userID );
			return user.groups.list();
		});
	}

	/**
	Get a list of all users in a given group.
	This requires the `EasyAuthPermissions.EAPListUsersInGroups` permission.
	**/
	public function getAllUsersInGroup( groupID:DatabaseID<Group> ):Outcome<List<User>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListUsersInGroups );
			var group = Group.manager.get( groupID );
			return group.users.list();
		});
	}

	/**
	Get a list of all permissions that have been granted to a user.
	This will include any permissions granted to groups that this user belongs to.
	This requires the `EasyAuthPermissions.EAPListUsersInGroups` permission.

	@return A list of the `EnumValue` permission values.
	**/
	public function getAllPermissionsForUser( userID:DatabaseID<User> ):Outcome<List<EnumValue>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListUserPermissions );
			var user = User.manager.get( userID );
			var groupIDs = [ for (g in user.groups) g.id ];
			var permissions = Permission.manager.search( $userID==userID.toInt() || $groupID in groupIDs );
			return permissions.map( function(p) {
				var parts = p.permission.split( ":" );
				var enumType = Type.resolveEnum( parts[0] );
				return Type.createEnum( enumType, parts[1] );
			});
		});
	}

	/**
	Create a new `User` in the database using the given username and password.
	This requires the `EasyAuthPermissions.EAPCreateUser` permission.
	**/
	public function createUser( username:String, password:String ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPCreateUser );
			var u = new User( username, password );
			u.save();
			return u;
		});
	}

	/**
	Create a new `Group` in the database using the given group name.
	This requires the `EasyAuthPermissions.EAPCreateUser` permission.
	**/
	public function createGroup( groupName:String ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPCreateGroup );
			var g = new Group( groupName );
			g.save();
			return g;
		});
	}

	private function userAllowedToAssignToGroup( group:Group ):Void {
		if ( !easyAuth.hasPermission( EAPAssignAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPAssignOwnGroup) ) {
				if ( easyAuth.getCurrentUser().groups.has(group)==false )
					throw HttpError.unauthorized( 'You are not in the group you are trying to assign users to' );
			}
			else throw HttpError.unauthorized( 'You do not have permission to assign users to groups' );
		}
	}

	/**
	Assign a `User` to a particular `Group`.

	If the current user is a member of the target group, they must have the `EasyAuthPermissions.EAPAssignAnyGroup` or `EasyAuthPermissions.EAPAssignOwnGroup` permissions.
	If the current user is not a member of the targer group, they must have the `EasyAuthPermissions.EAPAssignAnyGroup` permission.
	**/
	public function assignUserToGroup( userID:DatabaseID<User>, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var group = Group.manager.get( groupID );
			var user = User.manager.get( userID );
			userAllowedToAssignToGroup( group );
			user.groups.add( group );
			return Noise;
		});
	}

	/**
	Remove a `User` from a particular `Group`.

	If the current user is a member of the target group, they must have the `EasyAuthPermissions.EAPAssignAnyGroup` or `EasyAuthPermissions.EAPAssignOwnGroup` permissions.
	If the current user is not a member of the targer group, they must have the `EasyAuthPermissions.EAPAssignAnyGroup` permission.
	**/
	public function removeUserFromGroup( userID:DatabaseID<User>, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var user = User.manager.get( userID );
			var group = Group.manager.get( groupID );
			userAllowedToAssignToGroup( group );
			user.groups.remove( group );
			return Noise;
		});
	}

	private function userAllowedToAssignPermissions( permission:EnumValue ):Void {
		if ( !easyAuth.hasPermission( EAPAssignAnyUserPermission ) ) {
			if ( easyAuth.hasPermission(EAPAssignUserPermissionYouHave) ) {
				if ( easyAuth.getCurrentUser().can(permission)==false )
					throw HttpError.unauthorized( 'You do not have the $permission permission, so you cannot give it to anyone' );
			}
			else throw HttpError.unauthorized( 'You do not have permission to assign permissions' );
		}
	}

	/**
	Grant a `User` a particular permission.

	If the current user has this permission themselves, they they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` or `EasyAuthPermissions.EAPAssignUserPermissionYouHave` permissions.
	If the current user does not have this permission themselves, they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` permission.
	**/
	public function assignPermissionToUser( permission:EnumValue, userID:DatabaseID<User> ):Outcome<Noise,Error> {
		var errors = [];
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			var count = Permission.manager.count( $userID==userID.toInt() && $permission==pString );
			if ( count>1 ) {
				// In case we have some duplicates... delete them all and recreate just one.
				Permission.manager.delete( $userID==userID.toInt() && $permission==pString );
				count = 0;
			}
			if ( count==0 ) {
				var item = new Permission();
				item.permission = pString;
				item.userID = userID;
				item.insert();
			}
			return Noise;
		});
	}

	/**
	Grant a `Group` a particular permission.
	All `User`s in that group (and any future users) will then be considered to have that permission.

	If the current user has this permission themselves, they they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` or `EasyAuthPermissions.EAPAssignUserPermissionYouHave` permissions.
	If the current user does not have this permission themselves, they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` permission.
	**/
	public function assignPermissionToGroup( permission:EnumValue, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		var errors = [];
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			var count = Permission.manager.count( $groupID==groupID.toInt() && $permission==pString );
			if ( count>1 ) {
				// We have some duplicates... delete them all and recreate just one.
				Permission.manager.delete( $groupID==groupID.toInt() && $permission==pString );
				count = 0;
			}
			if ( count==0 ) {
				var item = new Permission();
				item.permission = pString;
				item.groupID = groupID;
				item.insert();
			}
			return Noise;
		});
	}

	/**
	Revoke a permission from a given `User`.

	If the current user has this permission themselves, they they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` or `EasyAuthPermissions.EAPAssignUserPermissionYouHave` permissions.
	If the current user is not a member of the targer group, they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` permission.
	**/
	public function revokePermissionFromUser( permission:EnumValue, userID:DatabaseID<User> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $userID==userID.toInt() && $permission==pString );
			return Noise;
		});
	}

	/**
	Revoke a permission from a particular `Group`.
	Users in that group will no longer be considered to have that permission, unless they had it assigned directly to their User, or to another group that they belong to.

	If the current user has this permission themselves, they they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` or `EasyAuthPermissions.EAPAssignUserPermissionYouHave` permissions.
	If the current user is not a member of the targer group, they must have the `EasyAuthPermissions.EAPAssignAnyUserPermission` permission.
	**/
	public function revokePermissionFromGroup( permission:EnumValue, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $groupID==groupID.toInt() && $permission==pString );
			return Noise;
		});
	}

	private function userAllowedToEditUsers( user:User ):Void {
		if ( !easyAuth.hasPermission( EAPEditAnyUser ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnUser) ) {
				if ( easyAuth.getCurrentUser().id!=user.id )
					throw HttpError.unauthorized( 'You are only allowed to edit your own user' );
			}
			else throw HttpError.unauthorized( 'You are not allowed to edit users, even your own' );
		}
	}

	/**
	Change the username of a particular `User` in the database.

	If the target user is the currently logged in user, they must have the `EasyAuthPermissions.EAPEditAnyUser` or `EasyAuthPermissions.EAPEditOwnUser` permissions.
	If the target user is not the currently logged in user, they must have the `EasyAuthPermissions.EAPEditAnyUser` permission.
	**/
	public function changeUsername( userID:DatabaseID<User>, newUsername:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var u = User.manager.get( userID );
			userAllowedToEditUsers( u );
			u.username = newUsername;
			u.save();
			return Noise;
		});
	}

	/**
	Change the password of the currently logged in user.

	The old password must be provided (and be verified with `this.authenticate()`) for the update to be successful.

	If the target user is the currently logged in user, they must have the `EasyAuthPermissions.EAPEditAnyUser` or `EasyAuthPermissions.EAPEditOwnUser` permissions.
	If the target user is not the currently logged in user, they must have the `EasyAuthPermissions.EAPEditAnyUser` permission.
	**/
	public function changeCurrentUserPassword( oldPassword:String, newPassword:String ):Surprise<Noise,Error> {
		if ( easyAuth.hasPermission(EAPChangePasswordOwnUser)==false )
			return Failure( HttpError.authError(ANoPermission(EAPChangePasswordOwnUser)) );
		var u = easyAuth.getCurrentUser();
		if ( u==null )
			return Failure( HttpError.authError(ANotLoggedIn) );

		return this.authenticate( u.username, oldPassword ).map(function(validLogin:Bool) {
			if ( validLogin ) {
				return wrapInOutcome(function() {
					u.setPassword( newPassword );
					u.save();
					return Noise;
				});
			}
			else {
				var error = HttpError.authError( ALoginFailed('Existing password not valid') );
				return Failure( error );
			}
		})
	}

	/**
	Change the password of a given `User`.

	A new salt will be generated and the password hashed using `User.setPassword()`, and the record updated in the database.

	The current user must have the `EasyAuthPermissions.EAPChangePasswordAnyUser` permission.
	**/
	public function changeAnyPassword( userID:DatabaseID<User>, newPassword:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPChangePasswordAnyUser );
			var u = User.manager.get( userID );
			u.setPassword( newPassword );
			u.save();
			return Noise;
		});
	}

	private function userAllowedToEditGroups( group:Group ):Void {
		if ( !easyAuth.hasPermission( EAPEditAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnGroup) ) {
				if ( easyAuth.getCurrentUser().groups.has(group)==false )
					throw HttpError.unauthorized( 'You are only allowed to edit groups you are in' );
			}
			else throw HttpError.unauthorized( 'You are not allowed to edit groups, even one you are in' );
		}
	}

	/**
	Change the name of a given `Group`.

	If the current user is a member of the target group, they must have the `EasyAuthPermissions.EAPEditAnyGroup` or `EasyAuthPermissions.EAPEditOwnGroup` permissions.
	If the current user is not a member of the targer group, they must have the `EasyAuthPermissions.EAPEditAnyGroup` permission.
	**/
	public function changeGroupName( groupID:DatabaseID<Group> , newName:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var g = Group.manager.get( groupID );
			userAllowedToEditGroups( g );
			g.name = newName;
			g.save();
			return Noise;
		});
	}

	private function wrapInOutcome<T>( fn:Void->T, ?pos:haxe.PosInfos ):Outcome<T,Error> {
		return
			try Success( fn() )
			catch (e:Dynamic) Failure( HttpError.wrap(e, 'Internal Server Error in ${pos.className}.${pos.methodName}(): $e', pos) );
	}
}
