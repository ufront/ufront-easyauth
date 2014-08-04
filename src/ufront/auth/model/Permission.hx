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

	#if server 
		public static function grantPermission(?u:User, ?g:Group, p:EnumValue)
		{
			var userID = (u!=null) ? u.id : null;
			var groupID = (g!=null) ? g.id : null;
			var pString = getPermissionID(p);
			var count = Permission.manager.count($groupID == groupID && $userID == userID && $permission == pString);
			if ( count>1 ) {
				// We have too many... delete them all and recreate just one.
				Permission.manager.delete($groupID == groupID && $userID == userID && $permission == pString);
				count = 0;
			}
			if ( count==0 ) {
				var item = new Permission();
				item.permission = pString;
				item.user = u;
				item.group = g;
				item.insert();
			}
		}

		public static function revokePermission(?u:User, ?g:Group, p:EnumValue)
		{
			var pString = getPermissionID(p);
			var userID = (u!=null) ? u.id : null;
			var groupID = (g!=null) ? g.id : null;
			var items = Permission.manager.search($groupID == groupID && $userID == userID && $permission == pString);
			for (item in items)
			{
				item.delete();
			}
		}
	#end
}