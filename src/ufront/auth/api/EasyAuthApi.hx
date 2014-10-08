package ufront.auth.api;

import ufront.api.UFApi;
import ufront.auth.model.*;
import ufront.auth.AuthError;
import ufront.auth.EasyAuthDBAdapter;
import ufront.auth.EasyAuth;
import ufront.auth.EasyAuthPermissions;
using tink.CoreApi;
using Lambda;

/**
	An API to conduct basic auth operations, from logging in to creating users and granting permissions.
**/
class EasyAuthApi extends UFApi {

	@inject public var easyAuth:EasyAuth;

	/**
		Attempt to login given a username and password.

		@param username The username of the user we wish to log in as.
		@param password The user entered password - this will be hashed with the same salt and compared to the hash in the database.
		@return `Success(user)` if the login was successful, or `Failure(AuthError)` if it failed.
	**/
	public function attemptLogin( username:String, password:String ):Outcome<User,AuthError> {
		return easyAuth.startSessionSync( new EasyAuthDBAdapter(username,password) );
	}

	/**
		Logout (end the current session).

		Please note this does not end the session, (the HttpSessionState is still alive, along with any cookies etc), it just ends the authentication, so you are no longer logged in as a user.

		@return `Success(user)` if the login was successful, or `Failure(AuthError)` if it failed.
	**/
	public function logout():Void {
		easyAuth.endSession();
	}
	
	public function getUser( userID:Int ):Outcome<User,Error> {
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
	
	public function getGroup( groupID:Int ):Outcome<Group,Error> {
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

	public function getAllGroupsForUser( userID:Int ):Outcome<List<Group>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListGroupsForUser );
			var user = User.manager.get( userID );
			return user.groups.list();
		});
	}

	public function getAllUsersInGroup( groupID:Int ):Outcome<List<User>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListUsersInGroups );
			var group = Group.manager.get( groupID );
			return group.users.list();
		});
	}

	public function getAllPermissionsForUser( userID:Int ):Outcome<List<EnumValue>,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPListUserPermissions );
			var user = User.manager.get( userID );
			var groupIDs = [ for (g in user.groups) g.id ];
			var permissions = Permission.manager.search( $userID==userID || $groupID in groupIDs );
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

	function userAllowedToAssignToGroup( group:Group ) {
		if ( !easyAuth.hasPermission( EAPAssignAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPAssignOwnGroup) ) {
				if ( easyAuth.currentUser.groups.has(group)==false )
					throw 'You are not in the group you are trying to assign users to.';
			}
			else throw 'You do not have permission to assign users to groups';
		}
	}

	public function assignUserToGroup( userID:Int, groupID:Int ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var group = Group.manager.get( groupID );
			var user = User.manager.get( userID );
			userAllowedToAssignToGroup( group );
			user.groups.add( group );
			return Noise;
		});
	}

	public function removeUserFromGroup( userID:Int, groupID:Int ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var user = User.manager.get( userID );
			var group = Group.manager.get( groupID );
			userAllowedToAssignToGroup( group );
			user.groups.remove( group );
			return Noise;
		});
	}

	function userAllowedToAssignPermissions( permission:EnumValue ) {
		if ( !easyAuth.hasPermission( EAPAssignAnyUserPermission ) ) {
			if ( easyAuth.hasPermission(EAPAssignUserPermissionYouHave) ) {
				if ( easyAuth.currentUser.can(permission)==false )
					throw 'You do not have the $permission permission, so you cannot give it to anyone.';
			}
			else throw 'You do not have permission to assign permissions.';
		}
	}

	public function assignPermissionToUser( permission:EnumValue, userID:Int ):Outcome<Noise,Error> {
		var errors = [];
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			var count = Permission.manager.count( $userID==userID && $permission==pString );
			if ( count>1 ) {
				// We have some duplicates... delete them all and recreate just one.
				Permission.manager.delete( $userID==userID && $permission==pString );
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

	public function assignPermissionToGroup( permission:EnumValue, groupID:Int ):Outcome<Noise,Error> {
		var errors = [];
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			var count = Permission.manager.count( $groupID==groupID && $permission==pString );
			if ( count>1 ) {
				// We have some duplicates... delete them all and recreate just one.
				Permission.manager.delete( $groupID==groupID && $permission==pString );
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

	public function revokePermissionFromUser( permission:EnumValue, userID:Int ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $userID==userID && $permission==pString );
			return Noise;
		});
	}

	public function revokePermissionFromGroup( permission:EnumValue, groupID:Int ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			userAllowedToAssignPermissions( permission );
			var pString = Permission.getPermissionID( permission );
			Permission.manager.delete( $groupID==groupID && $permission==pString );
			return Noise;
		});
	}

	function userAllowedToEditUsers( user:User ) {
		if ( !easyAuth.hasPermission( EAPEditAnyUser ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnUser) ) {
				if ( easyAuth.currentUser.id==user.id )
					throw 'You are only allowed to edit your own user.';
			}
			else throw 'You are not allowed to edit users, even your own.';
		}
	}

	public function changeUsername( userID:Int, newUsername:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var u = User.manager.get( userID );
			userAllowedToEditUsers( u );
			u.username = newUsername;
			u.save();
			return Noise;
		});
	}

	public function changeCurrentUserPassword( userID:Int, oldPassword:String, newPassword:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPChangePasswordOwnUser );
			var u = easyAuth.currentUser;
			// Don't let them change the password if they don't have the old password...
			var authAdapter = new EasyAuthDBAdapter( u.username, oldPassword );
			authAdapter.authenticateSync().sure();
			u.setPassword( newPassword );
			u.save();
			return Noise;
		});
	}

	public function changeAnyPassword( userID:Int, newPassword:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			easyAuth.requirePermission( EAPChangePasswordAnyUser );
			var u = User.manager.get( userID );
			u.setPassword( newPassword );
			u.save();
			return Noise;
		});
	}

	function userAllowedToEditGroups( group:Group ) {
		if ( !easyAuth.hasPermission( EAPEditAnyGroup ) ) {
			if ( easyAuth.hasPermission(EAPEditOwnGroup) ) {
				if ( easyAuth.currentUser.groups.has(group)==false )
					throw 'You are only allowed to edit groups you are in.';
			}
			else throw 'You are not allowed to edit groups, even one you are in.';
		}
	}

	public function changeGroupName( groupID:Int, newName:String ):Outcome<Noise,Error> {
		return wrapInOutcome(function() {
			var g = Group.manager.get( groupID );
			userAllowedToEditGroups( g );
			g.name = newName;
			g.save();
			return Noise;
		});
	}
	
	function wrapInOutcome<T>( fn:Void->T, ?pos:haxe.PosInfos ):Outcome<T,Error> {
		return 
			try Success( fn() )
			catch (e:Dynamic) Failure( Error.withData('Internal Server Error', e, pos) );
	}
}