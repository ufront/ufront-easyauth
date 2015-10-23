package ufront.auth.model;

import ufront.ORM;
import ufront.auth.model.*;
import sys.db.Types;

/**
A group that users can be part of.

Group can have multiple users, and each user can be in multiple groups.

Their main use in the EasyAuth model is to assign permissions to similar users.
For example a group named `Editors` might have the permissions `WritePost`, `EditPost` and `DeletePost`.
Any user who is part of the `Editors` group will automatically have these permisions too.

The table name for `Group` is `auth_group`.
A unique index is applied to the `name` column.
**/
@:table("auth_group")
@:index(name,unique)
class Group extends Object {
	/**
	Create a new group object.
	This will not save to the database automatically, you must call `this.save()` or `this.insert()`.

	@param name (optional) A shortcut for setting the group name.
	**/
	public function new( ?name:String=null ) {
		super();
		if ( name!=null )
			this.name = name;
	}

	/**
	The name for the group.

	The name must not be null, it must be unique, and must be less than 255 characters.
	**/
	public var name:SString<255>;

	/**
	The users who are in this group.

	See `EasyAuthApi.assignUserToGroup` and `EasyAuthApi.removeUserFromGroup` for a simple API to update user/group relationships.
	**/
	public var users:ManyToMany<Group,User>;

	/**
	The permissions that are assigned to this group.

	Any users who are members of this group will have these permissions.

	See `EasyAuthApi.assignPermissionToGroup()` and `EasyAuthApi.revokePermissionFromGroup()` for a simple API to assign and revoke group permissions.
	**/
	public var permissions:HasMany<Permission>;
}
