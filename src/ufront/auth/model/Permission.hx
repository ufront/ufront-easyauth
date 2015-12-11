package ufront.auth.model;

import ufront.auth.model.*;
import ufront.ORM;
import sys.db.Types;

/**
A permission that has been granted to a specific user or group.

Permissions are simple enums (with no arguments), and can be granted to either a `User` or a `Group`.

Please note that in Ufront the permission APIs (`UFAuthHandler.requirePermission()`, `UFAuthUser.can()` etc) take the enums as arguments, rather than these specific Permission objects.
These objects represent the assigning of a specific enum permission to a specific user or group.
For example:

```haxe
enum BlogPermissions {
	ReadPost;
	Comment;
	EditPost;
}
easyAuthApi.assignPermissionToUser( EditPost, auth.currentUser );
auth.requirePermission( EditPost );
auth.currentUser.can( EditPost );
```

Here `EditPost` is the enum permission.
The API call `assignPermissionToUser` will create a `Permission` object/row in the database, granting the current user the `EditPost` permission.

The table name for `Permission` is `auth_permission`.
A unique index is applied to the `permission` and `userID` columns.
Another unique index is also applied to the `permission` and `groupID` columns.
**/
@:table("auth_permission")
@:index(permission,userID,unique)
@:index(permission,groupID,unique)
class Permission extends Object {
	/**
	The permission that is being granted, represented as a string.
	Use `Permission.getPermissionString()` to get the correct string format.
	**/
	@:validate( ~/[A-Za-z0-9_\.]+:[A-Za-z0-9_]+/.match(_), "Invalid permission string, please use Permission.getPermissionString()" )
	public var permission:SString<255>;

	/** The `Group` that will be granted the permission. Either `group` or `user` must be supplied. **/
	public var group:Null<BelongsTo<Group>>;

	/** The `User` that will be granted the permission. Either `group` or `user` must be supplied. **/
	public var user:Null<BelongsTo<User>>;

	/**
	Check that either user or group is supplied during validation.
	**/
	override public function validate():Bool {
		super.validate();
		if ( groupID==null && userID==null ) {
			validationErrors.set( 'user', 'Either `user` or `group` must be set.' );
			validationErrors.set( 'group', 'Either `user` or `group` must be set.' );
		}
		return validationErrors.isValid;
	}

	/**
	Get the permission string for a given enum permission.

	This will take the format `some.package.EnumName:EnumConstructor`.
	For example, `Option.None` will be stored as `haxe.ds.Option:None`.

	If the enum takes any parameters, these will be ignored.
	**/
	public static function getPermissionString( e:EnumValue ):String {
		var enumName = Type.getEnumName(Type.getEnum(e));
		return enumName + ":" + Type.enumConstructor(e);
	}
}
