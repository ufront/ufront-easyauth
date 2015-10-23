package ufront.auth.model;

import ufront.ORM;
import sys.db.Types;
import ufront.auth.EasyAuthPermissions;
using Lambda;

/**
A user who can log into your app or website using a username and password.

The EasyAuth system is designed to have users, groups, and permissions that interact easily with the rest of Ufront.

Each user has:

- A unique database ID.
- A unique username.
- A password (which is hashed using `PBKDF2` and a random salt, it is not stored in plain-text).
- Relationships to multiple `Group`s (`ManyToMany`).
- Multiple permissions assigned specifically to this user (`HasMany`).

### Password hashing

It is extremely bad practice to store user passwords in plaintext, or even encrypted.
This is because, if your database server gets hacked, the hacker now knows your users' passwords.
And there's a good chance that your users also use the same passwords for other services.

Ufront does the following to secure your users' passwords:

- The user's password is never saved to the database.
- Rather, we use `PBKDF2` to generate a 1-way hash of the password. See https://en.wikipedia.org/wiki/PBKDF2
- To prevent hackers generating lookup tables easily, we generate a random 256bit salt.
- PBKDF2 is deliberately slow, so that generating a lookup table for each user (because each user has a different salt) is deliberately slow.

Password hashing is a complex topic. If you would like to understand more this post is a great place to start: https://crackstation.net/hashing-security.htm

If you have any further security recommendations please [open an Issue on Github](https://github.com/ufront/ufront-easyauth/issues) - we appreciate any advice.

__For example__, if I create a new user with the password `SoSecretive!`:

- It will create a random 32-character salt for this user. For example: `2?lRatY3u9u@Dq6F\bsYHqIVZBdLf4yA`.
- It will then use PBKDF2 to generate a hash using the password and salt.
  In my example, the hash is: `8b167c19a7bb7b7c65c36199348971bc6a2a199fe5cc472579ef6afddb899c33`.
- Both the salt and the hash are saved to the database. The password isn't saved.
- When they attempt to log in, we can use their attempted password, and the saved salt, to generate the same hash.
  If the hash matches, the password was correct, and we log them in.
- If the user tries to log in with the wrong password, it will generate a different hash, and the log in will fail.
- If two users use the same password, they will still have different salts, and so their hashes will be different.
  This means a hacker, even if they had our `auth_user` database, would need to build a look-up table for every single user if they wanted to learn their passwords.
  While possible, it would take a very long time - long enough for you to let your users know and take action as required.

### Storing extra data

It is common to want to store extra data, for example, profile information.
The easiest way to do this is with a `BelongsTo<User>` relationship:

```haxe
class UserProfile {
	public var user:BelongsTo<User>;
	public var website:SString<255>;
	public var age:STinyInt;
}
```

### Table details

The table name for `User` is `auth_user`.
A unique index is applied to the `username` column.
**/
@:table("auth_user")
@:index(username,unique)
class User extends Object implements ufront.auth.UFAuthUser {
	/**
	The username to use when logging in.

	Must not be null, up to 40 characters long, no other validation is performed.
	**/
	public var username:SString<40>;
	/**
	The randomly generated salt used for generating this user's password hash.

	32 characters long. This is set automatically during `setPassword()`.
	**/
	public var salt:SString<32>;

	/**
	The generated hash based on the user's password and salt.

	Up to 64 characters long. This is set automatically during `setPassword()`.
	**/
	public var password:SString<64>;

	/**
	A flag to specify if this user must change their password on the next logon.

	Please note it is up to the developer to respect this flag during the sign in process - it is not handled by EasyAuth automatically.
	**/
	public var forcePasswordChange:Bool;

	/**
	Permissions that have been assigned to this user.
	**/
	public var userPermissions:HasMany<Permission>;

	/**
	Groups that this user is a member of.
	**/
	public var groups:ManyToMany<User, Group>;

	/**
	The `userID` property required by the `UFAuthUser` interface.
	This returns the unique `this.username` for the current user.
	**/
	@:skip public var userID(get,null):String;

	// Private variables used to cache permission information.
	@:skip var hasSuperUserPermission:Null<Bool>;
	@:skip var allUserPermissions:List<String>;

	/**
	Create a new user object.

	This will not automatically save to the database.
	If username or password are provided they will be set (and the salt/password hash generated) automatically.
	**/
	public function new( ?username:String, ?password:String ) {
		super();
		#if server
			this.username = username;
			setPassword(password);
			this.forcePasswordChange = false;
		#end
	}

	/**
	Generate a new salt and password hash.

	This will not save the changes to the database, you must call `save()` to apply the changes.

	Please note this method only works on the server-side, and has no effect on the client.
	**/
	public function setPassword( password:String ):Void {
		#if server
			if ( password!=null ) {
				this.salt = generateSalt();
				this.password = generatePasswordHash(password, salt);
			}
			else {
				this.salt = "";
				this.password = "";
			}
		#end
	}

	/**
	Check if this user has a certain permission.

	Usage:

	```haxe
	if ( myUser.can(DriveCar) ) { driveCar(); }
	if ( myUser.can([DriveCar,BorrowParentsCar]) ) { borrowCar(); driveCar(); }
	```

	__Under the hood:__

	- A list of permissions this user has (directly or via the groups they belong to) will be loaded (the first time) and cached.
	- If the list failed to load (for example, if the object is being used client-side and the list was not loaded from the server), it will return **false**.
	- If the user is a super-user, (they have the `EAPCanDoAnything` permission) return **true**.
	- If `permission` is supplied, but the user doesn't have that permission, return **false**.
	- If `permissions` is supplied, and the user doesn't have any one of the given permissions, return **false**.
	- Otherwise, return **true**.
	**/
	public function can( ?permission:EnumValue, ?permissions:Iterable<EnumValue> ):Bool {
		loadUserPermissions();
		if (allUserPermissions==null) return false;
		if (isSuperUser()) return true;
		if (permission!=null) if ( !checkPermission(permission) ) return false;
		if (permissions!=null) for ( p in permissions ) if ( !checkPermission(p) ) return false;
		return true;
	}


	/**
	If the user has the `EAPCanDoAnything` permission we consider them a super-user, and they'll pass all permission checks.
	Please note when using the `EasyAuth` class we assume they are a super user if there are no super-users, because we consider the app to still be being set up.
	This assumption isn't made here - unless the user explicitly has the `EAPCanDoAnything` permission, we don't consider them a super user.
	**/
	inline function isSuperUser():Bool {
		if (hasSuperUserPermission==null)
			hasSuperUserPermission = checkPermission( EAPCanDoAnything );
		return hasSuperUserPermission;
	}

	function get_userID():String {
		return username;
	}

	inline function checkPermission( p:EnumValue ):Bool {
		return allUserPermissions.has( Permission.getPermissionString(p) );
	}

	function loadUserPermissions():Void {
		if ( allUserPermissions==null ) {
			#if server
				var groupIDs = [ for (g in groups) g.id ];
				var permissions = Permission.manager.search( $userID==this.id || $groupID in groupIDs );
				allUserPermissions = permissions.map( function(p) return p.permission );
			#else
				allUserPermissions = new List();
				// TODO: Remove this - ClientDS is deprecated.
				// Client-side permissions will need to be provided by another mechanism.
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

	/**
	A `User` object will automatically print `this.username`, to make for easier string interpolation: `Hello, $user`.
	**/
	override public function toString() {
		return username;
	}

	/**
	Remove the sensitive `this.salt` and `this.password` data.
	If you are going to serialize this object to share publicly or send to the client, it would be wise to call this method first.
	**/
	inline public function removeSensitiveData():Void {
		this.salt = "";
		this.password = "";
	}

	#if server
		/**
		Generate a new pseudo-random 32 character salt to use for generating a user's password hash.
		**/
		public static function generateSalt():String {
			var buff = new StringBuf();
			for (i in 0...32) {
				buff.addChar( Math.floor(Math.random()*74)+48 );
			}
			return buff.toString();
		}

		/**
		Generate a password hash for a given password and salt.

		This will use `PBKDF2.encode()` with the given password, salt, 500 iterations and byte size of 32.
		**/
		public static function generatePasswordHash(password:String, salt:String) {
			return PBKDF2.encode(password, salt, 500, 32);
		}
	#end
}
