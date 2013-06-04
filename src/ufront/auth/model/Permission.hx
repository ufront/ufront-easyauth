package ufront.auth.model;

import ufront.db.Object;
import ufront.auth.model.Group;
import sys.db.Types;

@:table("auth_group_permission")
class Permission extends Object
{
	public var permission:SString<255>;
	public var group:BelongsTo<Group>;

	public static function getPermissionID(e:EnumValue):String
	{
		var enumName = Type.getEnumName(Type.getEnum(e));
		return enumName + ":" + Type.enumConstructor(e);
	}

	#if server 
		public static function addPermission(g:Group, p:EnumValue)
		{
			var item = new Permission();
			item.permission = getPermissionID(p);
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

		public static function checkGroupHasPermission(g:Group, p:EnumValue):Bool
		{
			var pString = getPermissionID(p);
			var count = Permission.manager.count($groupID == g.id && $permission == pString);
			return (count > 0) ? true : false;
		}

		public static function checkUserHasPermission(u:User, p:EnumValue)
		{

		}
	#end
}