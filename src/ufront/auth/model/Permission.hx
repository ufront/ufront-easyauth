package ufront.auth.model;

import ufront.auth.model.User;
import ufront.db.Object;
import ufront.auth.model.Group;
import sys.db.Types;

@:table("auth_permission")
@:index(permission,groupID,unique)
@:index(permission,userID,unique)
class Permission extends Object
{
	public var permission:SString<255>;
	public var group:Null<BelongsTo<Group>>;
	public var user:Null<BelongsTo<User>>;

	public static function getPermissionID(e:EnumValue):String
	{
		var enumName = Type.getEnumName(Type.getEnum(e));
		return enumName + ":" + Type.enumConstructor(e);
	}
}