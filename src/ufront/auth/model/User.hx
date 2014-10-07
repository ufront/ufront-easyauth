package ufront.auth.model;

#if (client && ufront_clientds)
	import promhx.Promise;
#end
import ufront.db.Object;
import ufront.db.ManyToMany;
import sys.db.Types;
using Lambda;

@:table("auth_user")
@:index(username,unique)
class User extends Object implements ufront.auth.UFAuthUser
{
	public var username:SString<40>;
	public var salt:SString<32>;
	public var password:SString<64>;
	public var forcePasswordChange:Bool;

	public var userPermissions:HasMany<Permission>;
	public var groups:ManyToMany<User, Group>;
	@:skip public var userID(get,null):String;

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

	/** Check permissions.  if (myUser.can(DriveCar) or if (myUser.can([DriveCar,BorrowParentsCar])) { ... } */
	public function can( ?permission:EnumValue, ?permissions:Iterable<EnumValue> )
	{
		loadUserPermissions();
		if (allUserPermissions==null) return false; // Permissions not loaded yet...
		if (permission!=null) if ( !checkPermission(permission) ) return false;
		if (permissions!=null) for ( p in permissions ) if ( !checkPermission(p) ) return false;
		return true;
	}

	function get_userID() {
		return username;
	}

	function checkPermission( p:EnumValue ) 
	{
		return allUserPermissions.has( Permission.getPermissionID(p) );
	}

	@:skip var allUserPermissions:List<String>;
	function loadUserPermissions()
	{
		if (allUserPermissions == null)
		{
			#if server
				var groupIDs = [ for (g in groups) g.id ];
				var permissions = Permission.manager.search( $userID==this.id || $groupID in groupIDs );
				allUserPermissions = permissions.map( function(p) return p.permission );
			#else
				allUserPermissions = new List();
				#if ufront_clientds
					for ( g in groups )
						for ( p in g.permissions )
							allUserPermissions.add( p.permission );
					for ( p in userPermissions )
						allUserPermissions.add( p.permission );
				#end
			#end
		}
	}

	override public function toString()
	{
		return username;
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