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
using tink.CoreApi;
using Lambda;

/**
	An API to conduct basic auth operations, from logging in to creating users and granting permissions.
**/
class EasyAuthApi extends UFApi {

	#if server
		@inject public var easyAuth:EasyAuth;
		@inject public var injector:Injector;
	#end

	/**
		Attempt to login given a username and password.

		By default this will use `EasyAuthDBAdapter` to attempt to match the username and password to a valid user.
		If you wish to use a different auth adapter to check a username and password in a different way, you can inject a different `ufront.auth.UFAuthAdapter<ufront.auth.model.User>` class.
		The custom `UFAuthAdapter` will be instantiated by dependency injection, and have both "username" and "password" mapped as Strings.
		See `EasyAuthDBAdapter` for an example implementation.

		@param username The username of the user we wish to log in as.
		@param password The user entered password - this will be hashed with the same salt and compared to the hash in the database.
		@return `Success(user)` if the login was successful, or `Failure(AuthError)` if it failed.
	**/
	public function attemptLogin( username:String, password:String ):Outcome<User,TypedError<AuthError>> {
		injector.map( String, "username" ).toValue( username );
		injector.map( String, "password" ).toValue( password );
		if ( injector.hasMapping("ufront.auth.UFAuthAdapter<ufront.auth.model.User>")==false ) {
			injector.map( "ufront.auth.UFAuthAdapter<ufront.auth.model.User>" ).toClass( EasyAuthDBAdapter );
		}
		var authAdapter = injector.getValue( "ufront.auth.UFAuthAdapter<ufront.auth.model.User>" );
		return easyAuth.startSessionSync( authAdapter );
	}

	/**
		Logout (end the current session).

		Please note this does not end the session, (the HttpSessionState is still alive, along with any cookies etc), it just ends the authentication, so you are no longer logged in as a user.

		@return `Success(user)` if the login was successful, or `Failure(AuthError)` if it failed.
	**/
	public function logout():Void {
		easyAuth.endSession();
	}

	/**
		Authentification without storing sessions. Useful for development, testing or occasional client request.
		In production sending credentials to the server multiple times should be avoided, use login/sessions instead.

		@param username The username of the user we wish to authentificate.
		@param password The user entered password.
		@return `true` if username and password are valid, false otherwise.
	**/
	public function authenticate( username:String, password:String):Bool {
		var outcome = new EasyAuthDBAdapter(username, password).authenticateSync();
		switch (outcome) {
				case Success(data): return true;
				case Failure(_): return false;
		}
		return false;
	}

	public function getUser( userID:DatabaseID<User> ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.get( userID );
		});
	}

	public function getUserByUsername( username:String ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.select( $username==username );
		});
	}

	public function getAllUsers():Outcome<List<User>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllUsers );
			return User.manager.all();
		});
	}

	public function getGroup( groupID:DatabaseID<Group> ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.get( groupID );
		});
	}

	public function getGroupByName( name:String ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.select( $name==name );
		});
	}

	public function getAllGroups():Outcome<List<Group>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListAllGroups );
			return Group.manager.all();
		});
	}

	public function getAllGroupsForUser( userID:DatabaseID<User> ):Outcome<List<Group>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListGroupsForUser );
			var user = User.manager.get( userID );
			return user.groups.list();
		});
	}

	public function getAllUsersInGroup( groupID:DatabaseID<Group> ):Outcome<List<User>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListUsersInGroups );
			var group = Group.manager.get( groupID );
			return group.users.list();
		});
	}

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

	public function createUser( username:String, password:String ):Outcome<User,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPCreateUser );
			var u = new User( username, password );
			u.save();
			return u;
		});
	}

	public function createGroup( groupName:String ):Outcome<Group,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPCreateGroup );
			var g = new Group( groupName );
			g.save();
			return g;
		});
	}

	private function userAllowedToAssignToGroup( group:Group ) {
		if ( !easyAuth.hasPermission( EAPAssignAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPAssignOwnGroup) ) {
				if ( easyAuth.getCurrentUser().groups.has(group)==false )
					throw HttpError.unauthorized( 'You are not in the group you are trying to assign users to' );
			}
			else throw HttpError.unauthorized( 'You do not have permission to assign users to groups' );
		}
	}

	public function assignUserToGroup( userID:DatabaseID<User>, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var group = Group.manager.get( groupID );
			var user = User.manager.get( userID );
			userAllowedToAssignToGroup( group );
			user.groups.add( group );
			return Noise;
		});
	}

	public function removeUserFromGroup( userID:DatabaseID<User>, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var user = User.manager.get( userID );
			var group = Group.manager.get( groupID );
			userAllowedToAssignToGroup( group );
			user.groups.remove( group );
			return Noise;
		});
	}

	private function userAllowedToAssignPermissions( permission:EnumValue ) {
		if ( !easyAuth.hasPermission( EAPAssignAnyUserPermission ) ) {
			if ( easyAuth.hasPermission(EAPAssignUserPermissionYouHave) ) {
				if ( easyAuth.getCurrentUser().can(permission)==false )
					throw HttpError.unauthorized( 'You do not have the $permission permission, so you cannot give it to anyone' );
			}
			else throw HttpError.unauthorized( 'You do not have permission to assign permissions' );
		}
	}

	public function assignPermissionToUser( permission:EnumValue, userID:DatabaseID<User> ):Outcome<Noise,Error> {
		var errors = [];
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			var count = Permission.manager.count( $userID==userID.toInt() && $permission==pString );
			if ( count>1 ) {
				// We have some duplicates... delete them all and recreate just one.
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

	public function revokePermissionFromUser( permission:EnumValue, userID:DatabaseID<User> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $userID==userID.toInt() && $permission==pString );
			return Noise;
		});
	}

	public function revokePermissionFromGroup( permission:EnumValue, groupID:DatabaseID<Group> ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $groupID==groupID.toInt() && $permission==pString );
			return Noise;
		});
	}

	private function userAllowedToEditUsers( user:User ) {
		if ( !easyAuth.hasPermission( EAPEditAnyUser ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnUser) ) {
				if ( easyAuth.getCurrentUser().id!=user.id )
					throw HttpError.unauthorized( 'You are only allowed to edit your own user' );
			}
			else throw HttpError.unauthorized( 'You are not allowed to edit users, even your own' );
		}
	}

	public function changeUsername( userID:DatabaseID<User>, newUsername:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var u = User.manager.get( userID );
			userAllowedToEditUsers( u );
			u.username = newUsername;
			u.save();
			return Noise;
		});
	}

	public function changeCurrentUserPassword( userID:DatabaseID<User>, oldPassword:String, newPassword:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPChangePasswordOwnUser );
			var u = easyAuth.getCurrentUser();
			// Don't let them change the password if they don't have the old password...
			var authAdapter = new EasyAuthDBAdapter( u.username, oldPassword );
			authAdapter.authenticateSync().sure();
			u.setPassword( newPassword );
			u.save();
			return Noise;
		});
	}

	public function changeAnyPassword( userID:DatabaseID<User>, newPassword:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPChangePasswordAnyUser );
			var u = User.manager.get( userID );
			u.setPassword( newPassword );
			u.save();
			return Noise;
		});
	}

	private function userAllowedToEditGroups( group:Group ) {
		if ( !easyAuth.hasPermission( EAPEditAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnGroup) ) {
				if ( easyAuth.getCurrentUser().groups.has(group)==false )
					throw HttpError.unauthorized( 'You are only allowed to edit groups you are in' );
			}
			else throw HttpError.unauthorized( 'You are not allowed to edit groups, even one you are in' );
		}
	}

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
