package ufront.auth;

/**
	Permissions that are used by EasyAuth for setting up new users, groups, and permissions.

	Please note these permissions are enforced when using `ufront.auth.api.EasyAuthApi`, but they could be bypassed by using the models / database directly.
**/
enum EasyAuthPermissions {
	/** List all users. **/
	EAPListAllUsers;
	
	/** List all groups. **/
	EAPListAllGroups;
	
	/** List all permissions for a given user. **/
	EAPListUserPermissions;
	
	/** List all groups for any given user. **/
	EAPListGroupsForUser;
	
	/** List all users in any given group. **/
	EAPListUsersInGroups;
	
	/** Create a new user. **/
	EAPCreateUser;

	/** Assign a user to a group. **/
	EAPCreateGroup;

	/** Assign a user to a group that you already belong to. **/
	EAPAssignOwnGroup;

	/** Assign a user to any group. **/
	EAPAssignAnyGroup;

	/** Assign a permission you already have to another user or group. **/
	EAPAssignUserPermissionYouHave;

	/** Assign any permission to another user or group. **/
	EAPAssignAnyUserPermission;

	/** Edit your own user. **/
	EAPEditOwnUser;

	/** Edit any User. **/
	EAPEditAnyUser;

	/** Change the password for your own user. **/
	EAPChangePasswordOwnUser;

	/** Change the password for any User. **/
	EAPChangePasswordAnyUser;

	/** Edit a Group you belong to. **/
	EAPEditOwnGroup;

	/** Edit any Group. **/
	EAPEditAnyGroup;
	
	/** Can do anything - they are a superuser. **/
	EAPCanDoAnything;
}