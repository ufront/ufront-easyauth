package ufront.auth.model;

#if client 
	import promhx.Promise;
#end
import ufront.db.Object;
import ufront.db.ManyToMany;
import sys.db.Types;
using Lambda;

@:table("auth_user")

class User extends Object
{
	public var username:SString<40>;
	public var salt:SString<32>;
	public var password:SString<64>;
	public var forcePasswordChange:Bool;

	public var groups:ManyToMany<User, Group>;

	public function new(u:String, p:String)
	{
		super();
		#if server 
			this.username = u;
			this.setPassword( p );
			this.forcePasswordChange = false;
		#end 
	}

	/** Generate a new salt and password.  You will need to call save() yourself */
	public function setPassword(password:String)
	{
		#if server 
			this.salt = Random.string(32);
			this.password = generatePasswordHash(password, salt);
		#end
	}

	/** Check permissions.  if (myUser.can(DriveCar) && myUser.can(BorrowParentsCar)) { ... } */
	public function can(e:EnumValue)
	{
		loadUserPermissions();
		var str = Permission.getPermissionID(e);
		return allUserPermissions.has(str);
	}

	@:skip var allUserPermissions:List<String>;
	function loadUserPermissions()
	{
		if (allUserPermissions == null)
		{
			var groupIDs = groups.map(function (g:Group) { return g.id; });
			#if server 
				var permissionList = Permission.manager.search($groupID in groupIDs);
				allUserPermissions = permissionList.map(function (p:Permission) return p.permission);
				
			#else
				#if ufront_clientds
					var permissionList = new List();
					for ( g in groups )
						for ( p in g.permissions )
							permissionList.add( p );
					allUserPermissions = permissionList.map(function (p:Permission) return p.permission);
				#else 
					allUserPermissions = new List();
				#end
			#end
		}
	}

	#if server 
		public function removeSensitiveData()
		{
			this.salt = "";
			this.password = "";
			return this;
		}

		public static function generatePasswordHash(password:String, salt:String)
		{
			return PBKDF2.encode(password, salt, 500, 32);
		}
	#end
}