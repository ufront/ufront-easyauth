package ufront.auth.model;

import ufront.auth.model.User;
import ufront.db.Object;
import ufront.auth.model.Group;
import sys.db.Types;

@:table("auth_group_permission")
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

	#if server 
		public static function grantPermission(?u:User, ?g:Group, p:EnumValue)
		{
			var item = new Permission();
			item.permission = getPermissionID(p);
			item.user = u;
			item.group = g;
			item.insert();
		}

		public static function revokePermission(g:Group, p:EnumValue)
		{
			var pString = getPermissionID(p);
			var items = Permission.manager.search($groupID == g.id && $permission == pString);
			for (item in items)
			{
				item.delete();
			}
		}
	#end
}