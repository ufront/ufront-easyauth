package ufront.auth.api;

import ufront.api.UFApi;
import ufront.auth.model.*;
import ufront.auth.AuthError;
import ufront.auth.EasyAuthDBAdapter;
using tink.CoreApi;

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

	// TODO:
	// getAllUsers
	// getAllGroups
	// getAllGroupsForUser
	// getAllUsersInGroup
	// getAllPermissionsForUser
	// createUser
	// createGroup
	// assignUserToGroup
	// assignPermission(p,user,group)
	// changeUsername
	// changePassword
	// changeGroupName
}